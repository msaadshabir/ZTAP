package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClassificationProbeRejectsEarlyControlConnection(t *testing.T) {
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer control.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	denied := "http://" + listener.Addr().String()
	_ = listener.Close()
	var output bytes.Buffer
	if err := runClassificationProbe(denied, control.URL, time.Millisecond, 20*time.Millisecond, time.Second, "", filepath.Join(t.TempDir(), "release"), &output); err == nil {
		t.Fatal("an unclassified control TCP connection was accepted")
	}
	var record struct {
		Unknown uint64 `json:"unknown_tcp_connections"`
	}
	if err := json.NewDecoder(&output).Decode(&record); err != nil {
		t.Fatal(err)
	}
	if record.Unknown == 0 {
		t.Fatal("missing evidence of the early connection")
	}
}

func TestClassificationProbeAllowsReleasedControl(t *testing.T) {
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) }))
	defer control.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	denied := "http://" + listener.Addr().String()
	_ = listener.Close()
	release, stop := filepath.Join(t.TempDir(), "release"), filepath.Join(t.TempDir(), "stop")
	for _, path := range []string{release, stop} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := runClassificationProbe(denied, control.URL, time.Millisecond, 20*time.Millisecond, time.Second, stop, release, &output); err != nil {
		t.Fatal(err)
	}
	var record struct {
		Allowed uint64  `json:"allowed"`
		Unknown *uint64 `json:"unknown_tcp_connections"`
	}
	if err := json.NewDecoder(&output).Decode(&record); err != nil {
		t.Fatal(err)
	}
	if record.Allowed == 0 || record.Unknown == nil || *record.Unknown != 0 {
		t.Fatalf("released control evidence = %+v", record)
	}
}

func TestContinuityRejectsProhibitedConnections(t *testing.T) {
	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) }))
	defer allowed.Close()
	prohibited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer prohibited.Close()
	var output bytes.Buffer
	if err := runContinuityProbe(prohibited.URL, allowed.URL, 5*time.Millisecond, 50*time.Millisecond, time.Second, "", &output); err == nil {
		t.Fatal("a prohibited TCP connection was accepted because its response was not ok")
	}
}

func TestContinuityRequiresAllowedControl(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedTarget := "http://" + listener.Addr().String()
	_ = listener.Close()
	stop := filepath.Join(t.TempDir(), "stop")
	if err := os.WriteFile(stop, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runContinuityProbe(closedTarget, closedTarget, 5*time.Millisecond, 20*time.Millisecond, time.Second, stop, &output); err == nil {
		t.Fatal("an idle or broken allowed control was accepted")
	}
}
