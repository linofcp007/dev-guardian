package misses

import "sync"

func writeWithDefer(mu *sync.Mutex, m map[string]int, key string) error {
	mu.Lock()
	defer mu.Unlock()
	if key == "" {
		return nil
	}
	m[key] = 1
	return nil
}

// --- Written by the AUDITOR, and the reason the rule was redesigned. The
// --- shipped rule looked for `Lock()` without `defer Unlock()`, which fired
// --- on the two shapes where a `defer` would BE the bug, plus on a receiver
// --- that is not a mutex at all. The rule now looks for the bug itself — a
// --- `return` between the Lock and the Unlock — so all four are silent, and
// --- all four are DISCRIMINATING against the shipped rule.

// A fine-grained critical section. Deferring would hold the lock across the
// slow call below, which is precisely what this shape avoids.
func fineGrained(mu *sync.Mutex, m map[string]int, key string) int {
	mu.Lock()
	v := m[key]
	mu.Unlock()
	return expensive(v)
}

func expensive(v int) int { return v * 2 }

// Lock/unlock inside a loop body: a defer would not release until the whole
// function returned, which is a bug, not a fix.
func loopBody(mu *sync.Mutex, m map[string]int, keys []string) int {
	total := 0
	for _, k := range keys {
		mu.Lock()
		total += m[k]
		mu.Unlock()
	}
	return total
}

// Unlock deferred inside a closure that scopes the critical section.
func scopedClosure(mu *sync.Mutex, m map[string]int, key string) int {
	var v int
	func() {
		mu.Lock()
		defer mu.Unlock()
		v = m[key]
	}()
	return v
}

// Not a mutex at all: `$MU.Lock()` binds any receiver, and a file lock
// returns an error rather than blocking.
type fileLock struct{}

func (f *fileLock) Lock() error   { return nil }
func (f *fileLock) Unlock() error { return nil }

func flock(f *fileLock) error {
	if err := f.Lock(); err != nil {
		return err
	}
	return f.Unlock()
}

// The read half of an RWMutex, correctly released on every path. Its
// early-return twin is a hit fixture: the shipped rule could not see RLock
// at all.
func rlockNoEarlyReturn(mu *sync.RWMutex, m map[string]int, key string) int {
	mu.RLock()
	v := m[key]
	mu.RUnlock()
	return v
}
