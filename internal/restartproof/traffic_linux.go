//go:build linux && integration

// Package restartproof supplies independent workload sockets and outside peers
// for privileged Linux restart tests. It is never included in the agent binary.
package restartproof

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type Report struct {
	IngressAllowed uint64 `json:"ingress_allowed"`
	IngressDenied  uint64 `json:"ingress_prohibited"`
	Replies        uint64 `json:"established_replies"`
	AllowedPort    uint16 `json:"allowed_port,omitempty"`
	DeniedPort     uint16 `json:"denied_port,omitempty"`
}

type Harness struct {
	t       *testing.T
	Ports   Report
	Egress  [2]atomic.Uint64
	decoder *json.Decoder
	report  *os.File
	control *os.File
	stop    chan struct{}
	wg      sync.WaitGroup
	allowed *net.UDPConn
	denied  *net.UDPConn
}

// Start creates peer sockets outside the protected cgroup. The child creates
// every workload socket only after the parent verifies its cgroup membership.
func Start(t *testing.T, cgroup, helperTest string) *Harness {
	t.Helper()
	h := &Harness{t: t, stop: make(chan struct{})}
	var err error
	h.allowed, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	h.denied, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = h.allowed.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		close(h.stop)
		_ = h.allowed.Close()
		_ = h.denied.Close()
		h.wg.Wait()
	})
	for index, connection := range []*net.UDPConn{h.allowed, h.denied} {
		h.wg.Add(1)
		go func(index int, connection *net.UDPConn) {
			defer h.wg.Done()
			data := make([]byte, 8)
			for {
				_, peer, err := connection.ReadFromUDP(data)
				if err != nil {
					return
				}
				h.Egress[index].Add(1)
				if index == 0 {
					_, _ = connection.WriteToUDP(data, peer)
				}
			}
		}(index, connection)
	}
	pipe := func() (*os.File, *os.File) {
		t.Helper()
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
		return reader, writer
	}
	startRead, startWrite := pipe()
	reportRead, reportWrite := pipe()
	controlRead, controlWrite := pipe()
	h.report, h.control, h.decoder = reportRead, controlWrite, json.NewDecoder(reportRead)
	workload := exec.Command(os.Args[0], "-test.run=^"+helperTest+"$")
	workload.Env = append(os.Environ(), "ZTAP_RESTART_TRAFFIC_HELPER=1", "ZTAP_RESTART_ALLOWED="+h.allowed.LocalAddr().String(), "ZTAP_RESTART_DENIED="+h.denied.LocalAddr().String())
	workload.ExtraFiles = []*os.File{startRead, reportWrite, controlRead}
	workload.Stdout, workload.Stderr = os.Stdout, os.Stderr
	if err := workload.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = workload.Process.Kill(); _ = workload.Wait() })
	_ = startRead.Close()
	_ = reportWrite.Close()
	_ = controlRead.Close()
	if err := os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(workload.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := startWrite.Write([]byte{'1'}); err != nil {
		t.Fatal(err)
	}
	_ = startWrite.Close()
	_ = reportRead.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := h.decoder.Decode(&h.Ports); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *Harness) EgressPort() uint16 { return uint16(h.allowed.LocalAddr().(*net.UDPAddr).Port) }

// Begin keeps all four directional streams running through the entire outage.
func (h *Harness) Begin() {
	h.t.Helper()
	if _, err := h.control.Write([]byte{'g'}); err != nil {
		h.t.Fatal(err)
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		allowed, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(h.Ports.AllowedPort)})
		if err != nil {
			return
		}
		defer func() { _ = allowed.Close() }()
		denied, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(h.Ports.DeniedPort)})
		if err != nil {
			return
		}
		defer func() { _ = denied.Close() }()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		var sequence uint64
		for {
			select {
			case <-h.stop:
				return
			case <-ticker.C:
				sequence++
				data := make([]byte, 8)
				binary.BigEndian.PutUint64(data, sequence)
				_, _ = allowed.Write(data)
				_, _ = denied.Write(data)
			}
		}
	}()
}

func (h *Harness) Snapshot() Report {
	h.t.Helper()
	if _, err := h.control.Write([]byte{'s'}); err != nil {
		h.t.Fatal(err)
	}
	_ = h.report.SetReadDeadline(time.Now().Add(5 * time.Second))
	var report Report
	if err := h.decoder.Decode(&report); err != nil {
		h.t.Fatal(err)
	}
	return report
}

func (h *Harness) RequireProtected(after, before Report, beforeEgress uint64) {
	h.t.Helper()
	if after.IngressDenied != 0 || h.Egress[1].Load() != 0 || after.IngressAllowed <= before.IngressAllowed || after.Replies <= before.Replies || h.Egress[0].Load() <= beforeEgress {
		h.t.Fatalf("directional continuity failed: before=%+v after=%+v egress_allowed=%d egress_prohibited=%d", before, after, h.Egress[0].Load(), h.Egress[1].Load())
	}
}

func RunHelper(t *testing.T) {
	if os.Getenv("ZTAP_RESTART_TRAFFIC_HELPER") != "1" {
		t.Skip("helper")
	}
	start := os.NewFile(3, "socket creation gate")
	report := os.NewFile(4, "traffic report")
	control := os.NewFile(5, "traffic control")
	if _, err := io.ReadFull(start, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	_ = start.Close()
	allowed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = allowed.Close() }()
	denied, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = denied.Close() }()
	encoder := json.NewEncoder(report)
	initial := Report{AllowedPort: uint16(allowed.LocalAddr().(*net.UDPAddr).Port), DeniedPort: uint16(denied.LocalAddr().(*net.UDPAddr).Port)}
	if err := encoder.Encode(initial); err != nil {
		t.Fatal(err)
	}
	command := []byte{0}
	if _, err := io.ReadFull(control, command); err != nil || command[0] != 'g' {
		t.Fatalf("traffic start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var counters [3]atomic.Uint64
	var wg sync.WaitGroup
	receive := func(connection *net.UDPConn, counter *atomic.Uint64) {
		defer wg.Done()
		buffer := make([]byte, 8)
		for {
			_, _, err := connection.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			counter.Add(1)
		}
	}
	wg.Add(2)
	go receive(allowed, &counters[0])
	go receive(denied, &counters[1])
	connections := make([]*net.UDPConn, 0, 2)
	for _, addr := range []string{os.Getenv("ZTAP_RESTART_ALLOWED"), os.Getenv("ZTAP_RESTART_DENIED")} {
		peer, err := net.ResolveUDPAddr("udp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		connection, err := net.DialUDP("udp4", nil, peer)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	wg.Add(1)
	go receive(connections[0], &counters[2])
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		var sequence uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sequence++
				data := make([]byte, 8)
				binary.BigEndian.PutUint64(data, sequence)
				for _, connection := range connections {
					_, _ = connection.Write(data)
				}
			}
		}
	}()
	for {
		if _, err := io.ReadFull(control, command); err != nil {
			break
		}
		if command[0] != 's' && command[0] != 'q' {
			t.Fatal("invalid report request")
		}
		if command[0] == 'q' {
			cancel()
			_ = allowed.Close()
			_ = denied.Close()
			for _, connection := range connections {
				_ = connection.Close()
			}
			wg.Wait()
		}
		if err := encoder.Encode(Report{IngressAllowed: counters[0].Load(), IngressDenied: counters[1].Load(), Replies: counters[2].Load()}); err != nil {
			t.Fatal(err)
		}
		if command[0] == 'q' {
			break
		}
	}
}
