package alert

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

type DispatcherOptions struct {
	Sinks     []Sink
	QueueSize int
	Workers   int
	Timeout   time.Duration
}

type Dispatcher struct {
	sinks     []Sink
	queue     chan Alert
	workers   int
	timeout   time.Duration
	startOnce sync.Once
	closeOnce sync.Once
	wg        sync.WaitGroup
	dropped   uint64
	closed    uint32
}

func NewDispatcher(opts DispatcherOptions) (*Dispatcher, error) {
	if len(opts.Sinks) == 0 {
		return nil, errors.New("at least one sink is required")
	}

	queueSize := opts.QueueSize
	if queueSize <= 0 {
		queueSize = 128
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = 2
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return &Dispatcher{
		sinks:   append([]Sink(nil), opts.Sinks...),
		queue:   make(chan Alert, queueSize),
		workers: workers,
		timeout: timeout,
	}, nil
}

func (d *Dispatcher) Start(ctx context.Context) {
	d.startOnce.Do(func() {
		for i := 0; i < d.workers; i++ {
			d.wg.Add(1)
			go d.worker(ctx)
		}

		go func() {
			<-ctx.Done()
			d.Close()
		}()
	})
}

func (d *Dispatcher) Emit(a Alert) bool {
	if atomic.LoadUint32(&d.closed) == 1 {
		return false
	}

	if a.Timestamp.IsZero() {
		a.Timestamp = time.Now()
	}

	select {
	case d.queue <- a:
		return true
	default:
		atomic.AddUint64(&d.dropped, 1)
		return false
	}
}

func (d *Dispatcher) Dropped() uint64 {
	return atomic.LoadUint64(&d.dropped)
}

func (d *Dispatcher) Close() {
	d.closeOnce.Do(func() {
		atomic.StoreUint32(&d.closed, 1)
		close(d.queue)
		d.wg.Wait()
	})
}

func (d *Dispatcher) worker(ctx context.Context) {
	defer d.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case a, ok := <-d.queue:
			if !ok {
				return
			}
			if a.Timestamp.IsZero() {
				a.Timestamp = time.Now()
			}
			callCtx := ctx
			cancel := func() {}
			if d.timeout > 0 {
				callCtx, cancel = context.WithTimeout(ctx, d.timeout)
			}
			for _, sink := range d.sinks {
				_ = sink.Send(callCtx, a)
			}
			cancel()
		}
	}
}
