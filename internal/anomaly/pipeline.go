package anomaly

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

// PipelineOptions configures a Pipeline. Zero values fall back to the
// documented defaults (batch size 50, flush interval 10s).
type PipelineOptions struct {
	// Detector receives the buffered batches. Required.
	Detector Detector
	// BatchSize is the number of flows per detection batch (default 50).
	BatchSize int
	// FlushInterval is the maximum time a partial batch waits before being
	// flushed (default 10s).
	FlushInterval time.Duration
	// Threshold is the score above which a flow is reported as an anomaly
	// (default 50).
	Threshold float64
	// FailOpen, when true, drops failed batches and keeps the pipeline
	// running when the detection service is unreachable (default true).
	FailOpen bool
	// QueueSize is the capacity of the Submit buffer; Submit never blocks
	// and drops flows when the buffer is full (default 256).
	QueueSize int

	// OnScore is called with the highest score of each successfully
	// detected batch (metrics hook).
	OnScore func(score float64)
	// OnAnomaly is called once per flow whose score exceeds Threshold.
	OnAnomaly func(flow FlowRecord, score AnomalyScore)
	// OnError is called when a batch cannot be scored (service down, ...).
	OnError func(err error)
}

// Stats reports pipeline counters (all atomic; safe to read any time).
type Stats struct {
	FlowsReceived uint64 // flows accepted into the pipeline
	Flushes       uint64 // batches handed to the detector
	Detected      uint64 // flows scored by the service
	Anomalies     uint64 // flows with score above threshold
	Failures      uint64 // batches lost to detection errors
	Dropped       uint64 // flows dropped because the queue was full
}

// Pipeline buffers FlowRecords into batches and runs detection asynchronously,
// so the caller's hot path (flow ingestion / enforcement) never blocks on the
// detection service. When the service is unreachable and FailOpen is set,
// failed batches are counted and dropped; the pipeline keeps accepting flows.
type Pipeline struct {
	detector      Detector
	batchSize     int
	flushInterval time.Duration
	threshold     float64
	failOpen      bool
	onScore       func(score float64)
	onAnomaly     func(flow FlowRecord, score AnomalyScore)
	onError       func(err error)

	flowsCh chan FlowRecord // Submit buffer
	flushCh chan struct{}   // requests an immediate flush
	stopCh  chan struct{}   // fail-closed: closed when a batch fails and FailOpen is false
	doneCh  chan struct{}   // closed when the run loop exits

	flowsReceived atomic.Uint64
	flushes       atomic.Uint64
	detected      atomic.Uint64
	anomalies     atomic.Uint64
	failures      atomic.Uint64
	dropped       atomic.Uint64

	// batch is owned by the run loop goroutine exclusively.
	batch []FlowRecord
}

// NewPipeline validates the options and returns a ready pipeline.
func NewPipeline(opts PipelineOptions) (*Pipeline, error) {
	if opts.Detector == nil {
		return nil, fmt.Errorf("anomaly pipeline: detector is required")
	}

	batchSize := opts.BatchSize
	if batchSize <= 0 {
		batchSize = 50
	}
	flushInterval := opts.FlushInterval
	if flushInterval <= 0 {
		flushInterval = 10 * time.Second
	}
	queueSize := opts.QueueSize
	if queueSize <= 0 {
		queueSize = 256
	}

	return &Pipeline{
		detector:      opts.Detector,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		threshold:     opts.Threshold,
		failOpen:      opts.FailOpen,
		onScore:       opts.OnScore,
		onAnomaly:     opts.OnAnomaly,
		onError:       opts.OnError,
		flowsCh:       make(chan FlowRecord, queueSize),
		flushCh:       make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}, nil
}

// Start runs the pipeline until ctx is cancelled. Flows are fed via Submit.
// On exit the current partial batch is flushed; in-flight detections are
// allowed to finish.
func (p *Pipeline) Start(ctx context.Context) {
	go p.run(ctx)
}

// Wait blocks until the run loop has exited (after the context is cancelled
// or the pipeline is stopped).
func (p *Pipeline) Wait() {
	<-p.doneCh
}

// Submit hands a flow to the pipeline. It never blocks: when the queue is
// full the flow is dropped and counted. This is the enforcement hot path, so
// it must stay lock-free.
func (p *Pipeline) Submit(rec FlowRecord) {
	select {
	case p.flowsCh <- rec:
	default:
		p.dropped.Add(1)
	}
}

// Flush requests an immediate flush of the current partial batch. It is
// non-blocking; the run loop performs the flush.
func (p *Pipeline) Flush() {
	select {
	case p.flushCh <- struct{}{}:
	default:
	}
}

// Stats returns a snapshot of the pipeline counters.
func (p *Pipeline) Stats() Stats {
	return Stats{
		FlowsReceived: p.flowsReceived.Load(),
		Flushes:       p.flushes.Load(),
		Detected:      p.detected.Load(),
		Anomalies:     p.anomalies.Load(),
		Failures:      p.failures.Load(),
		Dropped:       p.dropped.Load(),
	}
}

func (p *Pipeline) run(ctx context.Context) {
	defer close(p.doneCh)

	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.drainFlows()
			p.flush()
			return
		case <-p.stopCh:
			p.drainFlows()
			p.flush()
			return
		case <-p.flushCh:
			// A flush request may arrive before the flows that triggered it;
			// drain what is already queued so the flush never no-ops on an
			// empty batch while flows are waiting.
			p.drainFlows()
			p.flush()
		case <-ticker.C:
			p.flush()
		case rec := <-p.flowsCh:
			p.flowsReceived.Add(1)
			p.batch = append(p.batch, rec)
			if len(p.batch) >= p.batchSize {
				p.flush()
			}
		}
	}
}

// drainFlows moves everything currently queued into the batch. Only the run
// loop calls it.
func (p *Pipeline) drainFlows() {
	for {
		select {
		case rec := <-p.flowsCh:
			p.flowsReceived.Add(1)
			p.batch = append(p.batch, rec)
		default:
			return
		}
	}
}

// flush hands the current batch to a detached detection goroutine. Only the
// run loop calls it.
func (p *Pipeline) flush() {
	if len(p.batch) == 0 {
		return
	}
	batch := p.batch
	p.batch = nil
	p.flushes.Add(1)
	go p.detect(batch)
}

// detect scores one batch and fans out the results. It never affects the
// ingestion path: failures are counted and reported via OnError.
func (p *Pipeline) detect(batch []FlowRecord) {
	scores, err := p.detector.DetectBatch(batch)
	if err != nil {
		p.failures.Add(1)
		if p.onError != nil {
			p.onError(fmt.Errorf("anomaly batch detection failed: %w", err))
		}
		if !p.failOpen {
			// Fail closed: detection can no longer be trusted, stop the
			// pipeline. The caller is notified via OnError.
			select {
			case <-p.stopCh:
			default:
				close(p.stopCh)
			}
		}
		return
	}

	p.detected.Add(uint64(len(batch)))
	var maxScore float64
	for i, score := range scores {
		if i >= len(batch) {
			break
		}
		if score.Score > maxScore {
			maxScore = score.Score
		}
		if score.Score > p.threshold {
			p.anomalies.Add(1)
			if p.onAnomaly != nil {
				p.onAnomaly(batch[i], score)
			}
		}
	}
	if p.onScore != nil {
		p.onScore(maxScore)
	}
}
