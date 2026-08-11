package auditqueue

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestQueue_RunsJobs(t *testing.T) {
	t.Parallel()
	q := New(Options{Size: 8, Workers: 2})
	q.Start()

	var count atomic.Int64
	var wg sync.WaitGroup
	const n = 5
	wg.Add(n)
	for range n {
		require.True(t, q.Submit(context.Background(), func(context.Context) {
			count.Add(1)
			wg.Done()
		}))
	}
	wg.Wait()
	require.NoError(t, q.Close())
	require.Equal(t, int64(n), count.Load())
}

func TestQueue_DrainsOnClose(t *testing.T) {
	t.Parallel()
	// Single worker, buffered: submit fast, then Close must drain everything.
	q := New(Options{Size: 64, Workers: 1})
	q.Start()

	var count atomic.Int64
	for range 32 {
		require.True(t, q.Submit(context.Background(), func(context.Context) {
			count.Add(1)
		}))
	}
	require.NoError(t, q.Close())
	require.Equal(t, int64(32), count.Load())
}

func TestQueue_DropsWhenFull(t *testing.T) {
	t.Parallel()
	// One worker held busy, size 1: after filling the buffer, further submits
	// must be dropped (return false) rather than block.
	q := New(Options{Size: 1, Workers: 1})
	q.Start()

	release := make(chan struct{})
	started := make(chan struct{})
	// Occupy the single worker.
	require.True(t, q.Submit(context.Background(), func(context.Context) {
		close(started)
		<-release
	}))
	<-started

	// Fill the buffer (size 1).
	require.True(t, q.Submit(context.Background(), func(context.Context) {}))
	// Now the buffer is full and the worker is busy: this must be dropped.
	require.False(t, q.Submit(context.Background(), func(context.Context) {}))

	close(release)
	require.NoError(t, q.Close())
}

func TestQueue_SubmitAfterCloseReturnsFalse(t *testing.T) {
	t.Parallel()
	q := New(Options{Size: 4, Workers: 1})
	q.Start()
	require.NoError(t, q.Close())

	require.False(t, q.Submit(context.Background(), func(context.Context) {
		t.Error("job must not run after close")
	}))
}

func TestQueue_CloseIsIdempotent(t *testing.T) {
	t.Parallel()
	q := New(Options{Size: 4, Workers: 1})
	q.Start()
	require.NoError(t, q.Close())
	require.NoError(t, q.Close())
}

func TestQueue_JobContextHasDeadline(t *testing.T) {
	t.Parallel()
	// Jobs must run under a bounded context so a hung backend cannot occupy a
	// worker forever.
	q := New(Options{Size: 1, Workers: 1, DispatchTimeout: 50 * time.Millisecond})
	q.Start()
	defer func() { require.NoError(t, q.Close()) }()

	deadlineCh := make(chan bool, 1)
	require.True(t, q.Submit(context.Background(), func(ctx context.Context) {
		_, ok := ctx.Deadline()
		deadlineCh <- ok
	}))
	require.True(t, <-deadlineCh, "job context must carry a deadline")
}

func TestQueue_RecoversFromPanickingJob(t *testing.T) {
	t.Parallel()
	// A panicking job must not kill the worker: a subsequent job still runs.
	q := New(Options{Size: 2, Workers: 1})
	q.Start()
	defer func() { require.NoError(t, q.Close()) }()

	require.True(t, q.Submit(context.Background(), func(context.Context) {
		panic("boom")
	}))

	done := make(chan struct{})
	require.True(t, q.Submit(context.Background(), func(context.Context) {
		close(done)
	}))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not survive a panicking job")
	}
}

func TestQueue_ConcurrentSubmitAndCloseNoPanic(t *testing.T) {
	t.Parallel()
	// Race the send-vs-close path: Submit must never panic on a closed channel.
	q := New(Options{Size: 4, Workers: 2})
	q.Start()

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			q.Submit(context.Background(), func(context.Context) {})
		})
	}
	time.Sleep(time.Millisecond)
	require.NoError(t, q.Close())
	wg.Wait()
}
