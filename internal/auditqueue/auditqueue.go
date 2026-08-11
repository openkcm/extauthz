// Package auditqueue provides a bounded, asynchronous worker pool for audit
// work. Both the Valkey rate-store round-trip and the audit.Logger HTTP POST are
// blocking network calls that must never run on the Check() hot path, so they
// are submitted here as jobs and executed on worker goroutines.
package auditqueue

import (
	"context"
	"sync"
	"time"

	"github.com/openkcm/extauthz/internal/metric"
)

// defaultDispatchTimeout bounds a single job's execution when Options does not
// specify one.
const defaultDispatchTimeout = 10 * time.Second

// Job is a unit of audit work executed on a worker goroutine. It receives a
// background context not tied to the (already-returned) request.
type Job func(ctx context.Context)

// Queue is a bounded async worker pool.
type Queue struct {
	metrics         *metric.Metrics
	ch              chan Job
	workers         int
	dispatchTimeout time.Duration

	wg sync.WaitGroup
	// mu guards the send-vs-close race: Submit holds RLock while sending, Close
	// holds Lock while closing ch, so ch is never sent on after it is closed.
	mu     sync.RWMutex
	closed bool
}

// Options configures a Queue.
type Options struct {
	// Metrics records dropped jobs and queue depth. May be nil.
	Metrics *metric.Metrics

	// Size bounds the number of buffered jobs. Values < 1 default to 1.
	Size int

	// Workers is the number of draining goroutines. Values < 1 default to 1.
	Workers int

	// DispatchTimeout bounds how long a single job may run before its context
	// is cancelled. Values <= 0 default to defaultDispatchTimeout.
	DispatchTimeout time.Duration
}

// New creates a Queue. Call Start before submitting and Close on shutdown.
func New(opts Options) *Queue {
	size := max(opts.Size, 1)
	workers := max(opts.Workers, 1)
	dispatchTimeout := opts.DispatchTimeout
	if dispatchTimeout <= 0 {
		dispatchTimeout = defaultDispatchTimeout
	}

	return &Queue{
		metrics:         opts.Metrics,
		ch:              make(chan Job, size),
		workers:         workers,
		dispatchTimeout: dispatchTimeout,
	}
}

// Start launches the worker goroutines that drain the queue.
func (q *Queue) Start() {
	for range q.workers {
		q.wg.Add(1)
		go q.worker()
	}
}

// Submit schedules a job for asynchronous execution. It never blocks: if the
// pool is saturated the job is dropped and counted. It returns false when the
// job was dropped.
func (q *Queue) Submit(ctx context.Context, job Job) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		return false
	}

	// Account for the enqueue before the send so the depth gauge is never
	// observed negative (a worker must not decrement before this increment
	// lands). Roll back if the buffer is full and the job is dropped.
	q.metrics.AddQueueDepth(ctx, 1)
	select {
	case q.ch <- job:
		return true
	default:
		q.metrics.AddQueueDepth(ctx, -1)
		q.metrics.IncDropped(ctx)
		return false
	}
}

// Close stops accepting new jobs and drains those already queued before
// returning. It is safe to call more than once.
func (q *Queue) Close() error {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return nil
	}
	q.closed = true
	close(q.ch)
	q.mu.Unlock()

	q.wg.Wait()
	return nil
}

func (q *Queue) worker() {
	defer q.wg.Done()
	for job := range q.ch {
		q.metrics.AddQueueDepth(context.Background(), -1)
		q.run(job)
	}
}

// run executes a single job under a bounded context, recovering from any panic
// so one misbehaving job cannot tear down the worker goroutine.
func (q *Queue) run(job Job) {
	defer func() {
		if r := recover(); r != nil {
			q.metrics.IncPanic(context.Background())
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), q.dispatchTimeout)
	defer cancel()
	job(ctx)
}
