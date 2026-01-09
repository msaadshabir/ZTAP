package apihttp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateSelfSignedCert(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ZTAP Test"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	return nil
}

func TestTLSServer(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	if err := generateSelfSignedCert(certPath, keyPath); err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	// Use a fixed port for simplicity in test or 0 for random.
	// Since we are calling ListenAndServe, we need a real port.
	// We can use a listener to get a free port then close it, but srv.Serve does its own Listen.
	// Actually, we can just use 127.0.0.1:0 and let the kernel decide.

	cfg := Config{
		Listen:      "127.0.0.1:0",
		AuthEnabled: false,
		TLS: TLSConfig{
			Enabled:  true,
			CertFile: certPath,
			KeyFile:  keyPath,
		},
	}

	srv, err := NewServer(ServerOptions{Config: cfg})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// We need to know the port to connect to.
	// srv.Serve uses ListenAndServe which doesn't easily expose the assigned port if we use :0.
	// Let's modify Serve to take a listener or just use a fixed port for this test if needed.
	// Alternatively, we can use httptest.NewUnstartedServer but that bypasses our Serve logic.

	// Better: Use a small hack to find a free port.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	srv.cfg.Listen = addr

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// Test HTTPS connection
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(fmt.Sprintf("https://%s/healthz", addr))
	if err != nil {
		t.Fatalf("failed to GET healthz via HTTPS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
