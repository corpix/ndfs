package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
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
	Prefix       string `json:"prefix"`
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

			// todo: sync chmod
			err = os.MkdirAll(filepath.Dir(path), os.ModePerm)
			if err != nil {
				log.Error().Err(err).Msgf("Failed to prepare directory hierarchy for %q", path)
				return
			}
			err = ob.GetFile(update.Name, path)
			if err != nil {
				log.Error().Err(err).Msgf("Failed to write file from object store %q", update.Name)
				return
			}
		}()
	}
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
				if event.Op.Has(fsnotify.Write) || event.Op.Has(fsnotify.Create) {
					_, err = ob.PutFile(event.Name)
					if err != nil {
						log.Error().Err(err).Msgf("Failed to put file %q", event.Name)
						continue
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Error().Err(err).Msg("Watcher error")
			}
		}
	}()

	for _, bindPath := range cfg.Bind {
		absBindPath, err := filepath.Abs(bindPath)
		if err != nil {
			log.Fatal().Err(err).Msgf("Failed to expand path %q", bindPath)
		}
		err = filepath.WalkDir(absBindPath, func(path string, d fs.DirEntry, err error) error {
			t := d.Type()
			switch {
			case t.IsDir():
				err = watcher.Add(path)
				if err != nil {
					log.Fatal().Err(err).Msgf("Failed to add watcher for %q", path)
				}
				log.Info().Msgf("Setup watcher for %q", path)
			case t.IsRegular():
				_, err = ob.PutFile(path)
				if err != nil {
					log.Fatal().Err(err).Msgf("Failed to put file into object store %q", path)
				}
			}
			return nil
		})
		if err != nil {
			log.Fatal().Err(err).Msgf("Failed to walk directory %q", bindPath)
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

	//

	cfg, err := config(ctx.String("config"))
	if err != nil {
		return err
	}

	wg := &sync.WaitGroup{}

	if cfg.Server != nil {
		wg.Add(1)
		go runServer(wg, cfg.Server)
	}
	if cfg.Client != nil {
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
