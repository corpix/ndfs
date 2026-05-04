package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigTreatsEmptyClientAsUnconfigured(t *testing.T) {
	dir := t.TempDir()
	caCert, serverCert, serverKey := writeServerTLSFiles(t, dir)

	cfgPath := filepath.Join(dir, "config.json")
	writeConfig(t, cfgPath, map[string]any{
		"client": map[string]any{},
		"server": map[string]any{
			"ca-cert": caCert,
			"cert":    serverCert,
			"key":     serverKey,
			"bind":    []string{dir},
		},
	})

	cfg, err := config(cfgPath, map[string]bool{"server": true, "client": true})
	if err != nil {
		t.Fatalf("config() returned error: %v", err)
	}
	if cfg.Client != nil {
		t.Fatalf("expected empty client stanza to be ignored, got %#v", cfg.Client)
	}
	if cfg.Server == nil || cfg.Server.tls == nil {
		t.Fatalf("expected server TLS config to be initialized")
	}
}

func TestConfigSkipsUnusedClientValidation(t *testing.T) {
	dir := t.TempDir()
	caCert, serverCert, serverKey := writeServerTLSFiles(t, dir)

	cfgPath := filepath.Join(dir, "config.json")
	writeConfig(t, cfgPath, map[string]any{
		"client": map[string]any{
			"ca-cert": "/does/not/exist",
			"cert":    "/does/not/exist",
			"key":     "/does/not/exist",
		},
		"server": map[string]any{
			"ca-cert": caCert,
			"cert":    serverCert,
			"key":     serverKey,
			"bind":    []string{dir},
		},
	})

	cfg, err := config(cfgPath, map[string]bool{"server": true})
	if err != nil {
		t.Fatalf("config() returned error: %v", err)
	}
	if cfg.Client == nil {
		t.Fatalf("expected client config to remain present when explicitly configured")
	}
	if cfg.Client.tls != nil {
		t.Fatalf("expected unused client TLS config to remain uninitialized")
	}
	if cfg.Server == nil || cfg.Server.tls == nil {
		t.Fatalf("expected server TLS config to be initialized")
	}
}

func writeConfig(t *testing.T, path string, cfg map[string]any) {
	t.Helper()

	fd, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}
	defer fd.Close()

	if err := json.NewEncoder(fd).Encode(cfg); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
}

func writeServerTLSFiles(t *testing.T, dir string) (string, string, string) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ndfs-test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  nil,
		DNSNames:     []string{"localhost"},
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create server cert: %v", err)
	}

	caPath := filepath.Join(dir, "ca-cert.pem")
	serverCertPath := filepath.Join(dir, "server-cert.pem")
	serverKeyPath := filepath.Join(dir, "server-key.pem")

	writePEMFile(t, caPath, "CERTIFICATE", caDER)
	writePEMFile(t, serverCertPath, "CERTIFICATE", serverDER)
	writePEMFile(t, serverKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))

	return caPath, serverCertPath, serverKeyPath
}

func writePEMFile(t *testing.T, path, blockType string, der []byte) {
	t.Helper()

	fd, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create PEM file %q: %v", path, err)
	}
	defer fd.Close()

	if err := pem.Encode(fd, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("failed to encode PEM file %q: %v", path, err)
	}
}
