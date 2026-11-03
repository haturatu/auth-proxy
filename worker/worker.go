package worker

import (
	"auth-proxy/types"
	"runtime"
	"sync/atomic"
)

// NewWorkerPool creates and starts a new worker pool.
// The number of workers is determined by the number of CPU cores, with a minimum of 2 and a max of 16.
func NewWorkerPool() *types.WorkerPool {
	numWorkers := runtime.NumCPU()
	if numWorkers > 16 {
		numWorkers = 16
	}
	if numWorkers < 2 {
		numWorkers = 2
	}

	pool := &types.WorkerPool{
		Workers:    numWorkers,
		TaskQueue:  make(chan func(), numWorkers*2),
		Active:     0,
	}

	for i := 0; i < numWorkers; i++ {
		pool.Wg.Add(1)
		go worker(pool)
	}

	return pool
}

// worker is a single worker goroutine that processes tasks from the TaskQueue.
func worker(p *types.WorkerPool) {
	defer p.Wg.Done()
	for task := range p.TaskQueue {
		atomic.AddInt64(&p.Active, 1)
		task()
		atomic.AddInt64(&p.Active, -1)
	}
}

// Submit adds a task to the worker pool's queue.
// This is a blocking operation if the queue is full.
func Submit(p *types.WorkerPool, task func()) {
	p.TaskQueue <- task
}

// ActiveWorkers returns the number of currently active (processing) workers.
func ActiveWorkers(p *types.WorkerPool) int64 {
	return atomic.LoadInt64(&p.Active)
}

// Close gracefully shuts down the worker pool.
// It closes the task queue and waits for all workers to finish their current tasks.
func Close(p *types.WorkerPool) {
	close(p.TaskQueue)
	p.Wg.Wait()
}
