package anomaly

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeDetector records the batches it receives and returns scripted scores.
type fakeDetector struct {
	mu      sync.Mutex
	batches [][]FlowRecord
	err     error
	scores  func(batch []FlowRecord) []AnomalyScore
}

func (f *fakeDetector) Detect(_ FlowRecord) (*AnomalyScore, error) {
	return nil, errors.New("not used")
}

func (f *fakeDetector) DetectBatch(batch []FlowRecord) ([]AnomalyScore, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = append(f.batches, append([]FlowRecord(nil), batch...))
	if f.err != nil {
		return nil, f.err
	}
	if f.scores != nil {
		return f.scores(batch), nil
	}
	scores := make([]AnomalyScore, len(batch))
	for i := range batch {
		scores[i] = AnomalyScore{Score: 10, IsAnomaly: false, Reason: "normal"}
	}
	return scores, nil
}

func (f *fakeDetector) Train(_ []FlowRecord) error { return nil }

func (f *fakeDetector) batchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.batches)
}

func (f *fakeDetector) batch(i int) []FlowRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.batches[i]
}

// waitFor polls cond until it returns true or the timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func TestPipelineBatchSizeFlush(t *testing.T) {
	det := &fakeDetector{}
	p, err := NewPipeline(PipelineOptions{Detector: det, BatchSize: 3, FlushInterval: time.Hour, Threshold: 50})
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	defer func() { cancel(); p.Wait() }()

	for i := range 3 {
		p.Submit(FlowRecord{SourceIP: "10.0.0.1", Port: 80 + i})
	}

	waitFor(t, 2*time.Second, func() bool { return det.batchCount() == 1 })
	got := det.batch(0)
	if len(got) != 3 || got[0].Port != 80 || got[2].Port != 82 {
		t.Fatalf("unexpected batch: %+v", got)
	}
	if p.Stats().FlowsReceived != 3 {
		t.Fatalf("expected 3 received, got %d", p.Stats().FlowsReceived)
	}
	if p.Stats().Flushes != 1 {
		t.Fatalf("expected 1 flush, got %d", p.Stats().Flushes)
	}
}

func TestPipelineIntervalFlush(t *testing.T) {
	det := &fakeDetector{}
	p, err := NewPipeline(PipelineOptions{Detector: det, BatchSize: 100, FlushInterval: 50 * time.Millisecond, Threshold: 50})
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	defer func() { cancel(); p.Wait() }()

	p.Submit(FlowRecord{SourceIP: "10.0.0.1", Port: 443})

	// Partial batch must be flushed by the interval ticker.
	waitFor(t, 2*time.Second, func() bool { return det.batchCount() == 1 })
	if len(det.batch(0)) != 1 {
		t.Fatalf("expected 1-flow batch, got %d", len(det.batch(0)))
	}
}

func TestPipelineManualFlush(t *testing.T) {
	det := &fakeDetector{}
	p, err := NewPipeline(PipelineOptions{Detector: det, BatchSize: 100, FlushInterval: time.Hour, Threshold: 50})
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	defer func() { cancel(); p.Wait() }()

	p.Submit(FlowRecord{SourceIP: "10.0.0.1", Port: 443})
	p.Flush()

	waitFor(t, 2*time.Second, func() bool { return det.batchCount() == 1 })
}

func TestPipelineFailOpen(t *testing.T) {
	det := &fakeDetector{err: errors.New("service down")}
	var mu sync.Mutex
	var errs []error
	p, err := NewPipeline(PipelineOptions{
		Detector:  det,
		BatchSize: 2,
		Threshold: 50,
		FailOpen:  true,
		OnError:   func(e error) { mu.Lock(); errs = append(errs, e); mu.Unlock() },
	})
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	defer func() { cancel(); p.Wait() }()

	// Two full batches with the service down: both fail, pipeline keeps running.
	p.Submit(FlowRecord{SourceIP: "10.0.0.1"})
	p.Submit(FlowRecord{SourceIP: "10.0.0.2"})
	waitFor(t, 2*time.Second, func() bool { return p.Stats().Failures >= 1 })
	p.Submit(FlowRecord{SourceIP: "10.0.0.3"})
	p.Submit(FlowRecord{SourceIP: "10.0.0.4"})
	waitFor(t, 2*time.Second, func() bool { return p.Stats().Failures >= 2 })

	mu.Lock()
	errCount := len(errs)
	mu.Unlock()
	if errCount != 2 {
		t.Fatalf("expected 2 OnError callbacks, got %d", errCount)
	}
	// The pipeline is still accepting flows after failures.
	if p.Stats().FlowsReceived != 4 {
		t.Fatalf("expected 4 received, got %d", p.Stats().FlowsReceived)
	}
}

func TestPipelineFailClosedStops(t *testing.T) {
	det := &fakeDetector{err: errors.New("service down")}
	p, err := NewPipeline(PipelineOptions{Detector: det, BatchSize: 1, Threshold: 50, FailOpen: false})
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	defer cancel()

	p.Submit(FlowRecord{SourceIP: "10.0.0.1"})
	waitFor(t, 2*time.Second, func() bool { return p.Stats().Failures == 1 })

	// Fail closed: the run loop exits after the failed batch.
	waitFor(t, 2*time.Second, func() bool {
		select {
		case <-p.doneCh:
			return true
		default:
			return false
		}
	})
}

func TestPipelineAnomalyCallbacks(t *testing.T) {
	det := &fakeDetector{scores: func(batch []FlowRecord) []AnomalyScore {
		scores := make([]AnomalyScore, len(batch))
		for i, rec := range batch {
			if rec.Port == 22 {
				scores[i] = AnomalyScore{Score: 85, IsAnomaly: true, Reason: "suspicious port 22"}
			} else {
				scores[i] = AnomalyScore{Score: 10, IsAnomaly: false, Reason: "normal"}
			}
		}
		return scores
	}}

	var mu sync.Mutex
	var anomalies []AnomalyScore
	var scored []float64
	p, err := NewPipeline(PipelineOptions{
		Detector:  det,
		BatchSize: 3,
		Threshold: 50,
		OnScore:   func(s float64) { mu.Lock(); scored = append(scored, s); mu.Unlock() },
		OnAnomaly: func(_ FlowRecord, s AnomalyScore) { mu.Lock(); anomalies = append(anomalies, s); mu.Unlock() },
	})
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	defer func() { cancel(); p.Wait() }()

	p.Submit(FlowRecord{SourceIP: "10.0.0.1", Port: 80})
	p.Submit(FlowRecord{SourceIP: "10.0.0.1", Port: 22})
	p.Submit(FlowRecord{SourceIP: "10.0.0.1", Port: 443})

	waitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(anomalies) == 1 && len(scored) == 1
	})

	mu.Lock()
	defer mu.Unlock()
	if anomalies[0].Score != 85 || anomalies[0].Reason != "suspicious port 22" {
		t.Fatalf("unexpected anomaly: %+v", anomalies[0])
	}
	if scored[0] != 85 {
		t.Fatalf("expected max score 85, got %v", scored[0])
	}
	if p.Stats().Anomalies != 1 || p.Stats().Detected != 3 {
		t.Fatalf("unexpected stats: %+v", p.Stats())
	}
}

func TestPipelineSubmitNeverBlocksAndDrops(t *testing.T) {
	det := &fakeDetector{scores: func(batch []FlowRecord) []AnomalyScore {
		scores := make([]AnomalyScore, len(batch))
		for i := range batch {
			scores[i] = AnomalyScore{Score: 10, IsAnomaly: false}
		}
		return scores
	}}
	p, err := NewPipeline(PipelineOptions{Detector: det, BatchSize: 1000, FlushInterval: time.Hour, QueueSize: 4, Threshold: 50})
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	defer func() { cancel(); p.Wait() }()

	// Overfill the queue: Submit must not block, excess flows are dropped.
	for i := range 100 {
		p.Submit(FlowRecord{SourceIP: "10.0.0.1", Port: i})
	}
	if p.Stats().Dropped == 0 {
		t.Fatalf("expected dropped flows, got %d", p.Stats().Dropped)
	}
}

func TestPipelineFlushOnShutdown(t *testing.T) {
	det := &fakeDetector{}
	p, err := NewPipeline(PipelineOptions{Detector: det, BatchSize: 100, FlushInterval: time.Hour, Threshold: 50})
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)

	p.Submit(FlowRecord{SourceIP: "10.0.0.1", Port: 443})
	cancel()
	p.Wait()

	// The partial batch is flushed when the run loop exits.
	waitFor(t, 2*time.Second, func() bool { return det.batchCount() == 1 })
}
