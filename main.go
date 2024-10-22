package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	console "github.com/mattn/go-isatty"
	natsServer "github.com/nats-io/nats-server/v2/server"
	natsClient "github.com/nats-io/nats.go"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"
	// "github.com/davecgh/go-spew/spew"
)

type Config struct {
	Client *ClientConfig `json:"client"`
	Server *ServerConfig `json:"server"`
}

type ClientConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	ReadyTimeout int    `json:"ready-timeout"`
	CACert       string `json:"ca-cert"`
	Cert         string `json:"cert"`
	Key          string `json:"key"`
	tls          *tls.Config
	Prefix       string         `json:"prefix"`
	Handler      *HandlerConfig `json:"handler"`
}

type HandlerConfig struct {
	Command     []string `json:"command"`
	command     []string
	Environment []string `json:"envirionment"`
}

type ServerConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	ReadyTimeout int    `json:"ready-timeout"`
	MaxPending   int    `json:"max-pending"`
	StoreDir     string `json:"store-dir"`
	CACert       string `json:"ca-cert"`
	Cert         string `json:"cert"`
	Key          string `json:"key"`
	tls          *tls.Config
	Bind         []string `json:"bind"`
}

//

const (
	FilesystemBucket = "files"
	FilesystemStream = "filesystem"
)

//

type Logger struct{ log zerolog.Logger }

func (l Logger) Noticef(format string, v ...any) { l.log.Info().Msgf(format, v...) }
func (l Logger) Warnf(format string, v ...any)   { l.log.Warn().Msgf(format, v...) }
func (l Logger) Fatalf(format string, v ...any)  { l.log.Fatal().Msgf(format, v...) }
func (l Logger) Errorf(format string, v ...any)  { l.log.Error().Msgf(format, v...) }
func (l Logger) Debugf(format string, v ...any)  { l.log.Debug().Msgf(format, v...) }
func (l Logger) Tracef(format string, v ...any)  { l.log.Trace().Msgf(format, v...) }

var _ = (natsServer.Logger)(&Logger{})

var (
	verbose bool
	debug   bool
)

func app() *cli.App {
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"c"},
			Usage:   "configuration file path",
			Value:   "config.json",
		},
		&cli.BoolFlag{
			Name:  "verbose",
			Usage: "be more verbose about operations performed",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "debug",
			Usage: "be even more verbose about operations performed",
			Value: false,
		},
		&cli.StringFlag{
			Name:  "services",
			Usage: "comma separated list of services to run (if they are configured)",
			Value: "server,client",
		},
	}
	app.Action = run
	return app
}

func config(path string) (*Config, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open ocnfiguration file %q", path)
	}
	defer fd.Close()

	var cfg Config
	err = json.NewDecoder(fd).Decode(&cfg)
	if err != nil {
		return nil, err
	}

	if cfg.Server == nil && cfg.Client == nil {
		return nil, errors.New("neither server or client is ocnfigured, exiting")
	}

	if cfg.Client != nil {
		if cfg.Client.Host == "" {
			cfg.Client.Host = "127.0.0.1"
		}
		if cfg.Client.Port == 0 {
			cfg.Client.Port = 13666
		}
		if cfg.Client.ReadyTimeout == 0 {
			cfg.Client.ReadyTimeout = 15
		}
		caCert, err := os.ReadFile(cfg.Client.CACert)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read CA cert %q", cfg.Client.CACert)
		}
		certPool := x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM(caCert); !ok {
			return nil, errors.New("failed to append CA certificate")
		}
		cert, err := tls.LoadX509KeyPair(cfg.Client.Cert, cfg.Client.Key)
		if err != nil {
			return nil, err
		}
		cfg.Client.tls = &tls.Config{
			ServerName:   cfg.Client.Host,
			Certificates: []tls.Certificate{cert},
			RootCAs:      certPool,
			MinVersion:   tls.VersionTLS12,
		}
		if cfg.Client.Handler != nil {
			if len(cfg.Client.Handler.Command) > 0 {
				cfg.Client.Handler.command = append(cfg.Client.Handler.command, cfg.Client.Handler.Command...)
				cfg.Client.Handler.command[0], err = exec.LookPath(cfg.Client.Handler.Command[0])
				if err != nil {
					return nil, errors.Wrapf(
						err, "failed to resolve executable path for command %v",
						cfg.Client.Handler.Command,
					)
				}
			}
		}
	}

	if cfg.Server != nil {
		if cfg.Server.Host == "" {
			cfg.Server.Host = "127.0.0.1"
		}
		if cfg.Server.Port == 0 {
			cfg.Server.Port = 13666
		}
		if cfg.Server.ReadyTimeout == 0 {
			cfg.Server.ReadyTimeout = 15
		}
		if cfg.Server.MaxPending == 0 {
			cfg.Server.MaxPending = 256
		}
		if cfg.Server.StoreDir == "" {
			cfg.Server.StoreDir = "./store"
		}
		caCert, err := os.ReadFile(cfg.Server.CACert)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read CA cert %q", cfg.Server.CACert)
		}
		certPool := x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM(caCert); !ok {
			return nil, errors.New("failed to append CA certificate")
		}
		cert, err := tls.LoadX509KeyPair(cfg.Server.Cert, cfg.Server.Key)
		if err != nil {
			return nil, err
		}
		cfg.Server.tls = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certPool,
			MinVersion:   tls.VersionTLS12,
		}
	}

	return &cfg, nil
}

func runClient(wg *sync.WaitGroup, cfg *ClientConfig) {
	defer wg.Done()
	defer log.Warn().Msg("Client stopped")
	log.Info().Msg("Starting client...")
	nc, err := natsClient.Connect(
		fmt.Sprintf("tls://%s:%d", cfg.Host, cfg.Port),
		natsClient.Secure(cfg.tls),
		natsClient.RetryOnFailedConnect(true),
		natsClient.MaxReconnects(2),
		natsClient.ReconnectJitter(500*time.Millisecond, 2*time.Second),
		natsClient.Timeout(5*time.Second),
	)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to connect to %q:%d", cfg.Host, cfg.Port)
	}

	connected := make(chan struct{})
	go func() {
		for {
			time.Sleep(10 * time.Millisecond)
			err := nc.LastError()
			if err != nil {
				log.Fatal().Err(err).Msg("Client failed to connect")
			}
			if nc.IsConnected() {
				connected <- struct{}{}
			}
		}
	}()
	select {
	case <-connected:
	case <-time.After(time.Duration(cfg.ReadyTimeout * int(time.Second))):
		log.Fatal().Msgf("Client connection not ready after %d seconds", cfg.ReadyTimeout)
	}
	log.Info().Msg("Client is ready")

	js, err := nc.JetStream()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create nats jetstream")
	}
	ob, err := js.ObjectStore(FilesystemBucket)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create nats object store for files")
	}

	watcher, err := ob.Watch()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create nats object store watcher")
	}
	updates := make(chan *natsClient.ObjectInfo)
	go func() {
		for update := range updates {
			if cfg.Handler != nil {
				if len(cfg.Handler.Command) > 0 {
					cmd := exec.Command(cfg.Handler.command[0], cfg.Handler.command[1:]...)
					env := os.Environ()
					env = append(env, cfg.Handler.Environment...)
					env = append(env, []string{
						fmt.Sprintf("NDFS_UPDATE_NAME=%s", update.Name),
						fmt.Sprintf("NDFS_UPDATE_MODE=%s", update.Metadata["mode"]),
						fmt.Sprintf("NDFS_UPDATE_UID=%s", update.Metadata["uid"]),
						fmt.Sprintf("NDFS_UPDATE_GID=%s", update.Metadata["gid"]),
						fmt.Sprintf("NDFS_UPDATE_ISDIR=%s", update.Metadata["isdir"]),
					}...)
					cmd.Env = env
					output, err := cmd.CombinedOutput()
					if err != nil {
						log.Error().Err(err).Msgf("Command handler %v failure", cfg.Handler.Command)
						continue
					}
					log.Info().Str("output", string(output)).Msgf("Command handler %v finished", cfg.Handler.Command)
				}
			}
		}
	}()
	for update := range watcher.Updates() {
		if update == nil {
			continue
		}
		log.Info().
			Str("digest", update.Digest).
			Str("name", update.Name).
			Msg("Object changed")
		func() {
			path := update.Name
			if cfg.Prefix != "" {
				path = filepath.Join(cfg.Prefix, path)
			}
			pathAbs, err := filepath.Abs(path)
			if err != nil {
				log.Error().Err(err).Msgf("Failed to resolve path %q", path)
				return
			}
			path = pathAbs

			err = os.MkdirAll(filepath.Dir(path), os.ModePerm)
			if err != nil {
				log.Error().Err(err).Msgf("Failed to prepare directory hierarchy for %q", path)
				return
			}
			objInfo, err := ob.GetInfo(update.Name, natsClient.GetObjectInfoShowDeleted())
			if err != nil {
				log.Error().Err(err).Msgf("Failed to get file info from object store %q", update.Name)
				return
			}
			if objInfo.Deleted {
				err = os.RemoveAll(path)
				if err != nil && !os.IsNotExist(err) {
					log.Error().Err(err).Msgf("Failed to remove file from filesystem %q", update.Name)
					return
				}
			} else {
				var isDir bool
				metaIsDir, ok := objInfo.Metadata["isdir"]
				if ok {
					isDir, err = strconv.ParseBool(metaIsDir)
					if err != nil {
						log.Error().Err(err).Msgf("Failed to parse isdir meta %q for %q", metaIsDir, update.Name)
						return
					}
				}
				if isDir {
					err = os.Mkdir(path, os.ModePerm)
					if err != nil && !os.IsExist(err) {
						log.Error().Err(err).Msgf("Failed to create directory %q", path)
						return
					}
				} else {
					err = ob.GetFile(update.Name, path)
					if err != nil {
						log.Error().Err(err).Msgf("Failed to download file from object store %q", update.Name)
						return
					}
				}
				mode, ok := objInfo.Metadata["mode"]
				if ok && mode != "" {
					fileMode, err := strconv.ParseUint(mode, 10, 32)
					if err != nil {
						log.Error().Err(err).Msgf("Failed to parse file mode %q from metadata %q", mode, update.Name)
						return
					}
					err = os.Chmod(path, os.FileMode(fileMode))
					if err != nil {
						log.Error().Err(err).Msgf("Failed to chmod file %q", path)
						return
					}
				}
			}
			updates <- update
		}()
	}
}

func putObject(ob natsClient.ObjectStore, path string, op fsnotify.Op) (*natsClient.ObjectInfo, error) {
	if op.Has(fsnotify.Remove) {
		info, err := ob.GetInfo(path)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get info from object store for %q", path)
		}
		err = ob.Delete(path)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to delete info from object store for %q", path)
		}
		return info, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to os stat %q", path)
	}
	sys := info.Sys().(*syscall.Stat_t)
	meta := &natsClient.ObjectMeta{
		Name: path,
		Metadata: map[string]string{
			"mode":  strconv.FormatUint(uint64(info.Mode()), 10),
			"uid":   strconv.FormatUint(uint64(sys.Uid), 10),
			"gid":   strconv.FormatUint(uint64(sys.Gid), 10),
			"isdir": strconv.FormatBool(info.IsDir()),
		},
	}
	switch {
	case op.Has(fsnotify.Chmod) || info.IsDir():
		if info.IsDir() {
			_, err = ob.PutBytes(path, nil)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to put bytes into object store for %q", path)
			}
		}
		err = ob.UpdateMeta(path, meta)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to update meta in object store for %q", path)
		}
		objInfo, err := ob.GetInfo(path)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get info from object store for %q", path)
		}
		return objInfo, nil
	default:
		f, err := os.Open(path)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to os open %q", path)
		}
		defer f.Close()
		objInfo, err := ob.Put(meta, f)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to put into object store for %q", path)
		}
		return objInfo, nil
	}
}

func walkDir(root string, watcher *fsnotify.Watcher, ob natsClient.ObjectStore) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		t := d.Type()
		switch {
		case t.IsDir():
			var alreadyWatched bool
			for _, watched := range watcher.WatchList() {
				if path == watched {
					alreadyWatched = true
					break
				}
			}
			if !alreadyWatched {
				err = watcher.Add(path)
				if err != nil {
					log.Fatal().Err(err).Msgf("Failed to add watcher for %q", path)
				}
				log.Info().Msgf("Setup watcher for %q", path)
			}
		}
		_, err = putObject(ob, path, 0)
		if err != nil {
			log.Fatal().Err(err).Msgf("Failed to put file into object store %q", path)
		}
		return nil
	})
}

func runServer(wg *sync.WaitGroup, cfg *ServerConfig) {
	defer wg.Done()
	defer log.Warn().Msg("Server stopped")
	log.Info().Msg("Starting server...")

	opts := &natsServer.Options{
		Host:       cfg.Host,
		Port:       cfg.Port,
		TLSConfig:  cfg.tls,
		TLS:        true,
		TLSVerify:  true,
		TLSTimeout: 5,
		JetStream:  true,
		StoreDir:   cfg.StoreDir,
	}
	ns, err := natsServer.NewServer(opts)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create server")
	}
	ns.SetLoggerV2(
		Logger{log: log.With().Str("logger", "nats").Logger()},
		true, true, true,
	)

	go ns.Start()
	if !ns.ReadyForConnections(time.Duration(cfg.ReadyTimeout * int(time.Second))) {
		log.Fatal().Msgf("Server not ready to accept connections after %d seconds", cfg.ReadyTimeout)
	}

	nc, err := natsClient.Connect("", natsClient.InProcessServer(ns))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create an in-process nats connection")
	}
	js, err := nc.JetStream(natsClient.PublishAsyncMaxPending(cfg.MaxPending))
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create nats jetstream")
	}
	js.AddStream(&natsClient.StreamConfig{
		Name:    FilesystemStream,
		Storage: natsClient.FileStorage,
	})
	ob, err := js.CreateObjectStore(&natsClient.ObjectStoreConfig{Bucket: FilesystemBucket})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create nats object store for files")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create fsnotify watcher")
	}
	defer watcher.Close()
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				log.Info().Msgf("Event %s on %q", event.Op, event.Name)
				if !event.Op.Has(fsnotify.Remove) {
					t, err := os.Stat(event.Name)
					if err != nil {
						log.Error().Err(err).Msgf("Failed to stat file %q", event.Name)
						continue
					}
					if t.IsDir() && event.Op.Has(fsnotify.Create) {
						err = walkDir(event.Name, watcher, ob)
						if err != nil {
							log.Error().Err(err).Msgf("Failed to walk dir %q", event.Name)
						}
						continue
					}
				}
				_, err = putObject(ob, event.Name, event.Op)
				if err != nil {
					log.Error().Err(err).Msgf("Failed to put file %q", event.Name)
					continue
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Error().Err(err).Msg("Watcher error")
			}
		}
	}()

	for _, path := range cfg.Bind {
		absPath, err := filepath.Abs(path)
		if err != nil {
			log.Fatal().Err(err).Msgf("Failed to expand path %q", path)
		}
		err = watcher.Add(absPath)
		if err != nil {
			log.Fatal().Err(err).Msgf("Failed to add watcher for %q", path)
		}
		err = walkDir(absPath, watcher, ob)
		if err != nil {
			log.Fatal().Err(err).Msgf("Failed to walk directory %q", path)
		}
	}

	ns.WaitForShutdown()
}

func run(ctx *cli.Context) error {
	verbose = ctx.Bool("verbose")
	if verbose {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	}

	debug = ctx.Bool("debug")
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	services := strings.Split(ctx.String("services"), ",")
	serviceMap := map[string]bool{}
	for _, service := range services {
		serviceMap[service] = true
	}

	//

	cfg, err := config(ctx.String("config"))
	if err != nil {
		return err
	}

	wg := &sync.WaitGroup{}

	if cfg.Server != nil && serviceMap["server"] {
		wg.Add(1)
		go runServer(wg, cfg.Server)
	}
	if cfg.Client != nil && serviceMap["client"] {
		wg.Add(1)
		go runClient(wg, cfg.Client)
	}

	wg.Wait()
	log.Info().Msg("Exiting")

	return nil
}

var log zerolog.Logger

func init() {
	var w io.Writer = os.Stderr
	if console.IsTerminal(os.Stderr.Fd()) {
		w = zerolog.ConsoleWriter{Out: os.Stderr}
	}
	log = zerolog.New(w).With().Timestamp().Logger()
}

func main() {
	app().RunAndExitOnError()
}
