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

// The early-unlock idiom: every early return releases the lock first. The
// rule matched it while it was `Lock() ... return ... Unlock()` — the `...`
// reaches into the `if`, and nothing excluded an Unlock before the return
// (review 3.6.1, measured on Semgrep 1.182.0).
func earlyUnlock(mu *sync.Mutex, m map[string]int, key string) error {
	mu.Lock()
	if key == "" {
		mu.Unlock()
		return nil
	}
	m[key] = 1
	mu.Unlock()
	return nil
}

// Its read-lock twin (crypto/tls, os/pipe_unix.go in the Go 1.27.3 tree).
// Without it the RUnlock exclusion had no fixture, only real code, behind it.
func earlyRUnlock(mu *sync.RWMutex, m map[string]int, key string) int {
	mu.RLock()
	if key == "" {
		mu.RUnlock()
		return 0
	}
	v := m[key]
	mu.RUnlock()
	return v
}

// --- Review 3.7.0, measured on the Go 1.27.3 standard library: the DEFERRED
// --- spelling of the same idiom. A deferred Unlock runs at every return of
// --- the function, so nothing after it skips anything. 21 of the 39
// --- findings 3.6.1 left on that tree were these three shapes.

// net/http/httputil's ServerConn: defer, then return, inside the branch.
func deferredEarlyUnlock(mu *sync.Mutex, m map[string]int, key string) error {
	mu.Lock()
	if key == "" {
		defer mu.Unlock()
		return nil
	}
	m[key] = 1
	mu.Unlock()
	return nil
}

func deferredEarlyRUnlock(mu *sync.RWMutex, m map[string]int, key string) int {
	mu.RLock()
	if key == "" {
		defer mu.RUnlock()
		return 0
	}
	v := m[key]
	mu.RUnlock()
	return v
}

// net/http's gzipReader.acquire: a deferred Unlock at the top, and the lock
// dropped and retaken by hand around a call that may block. Every return is
// covered by the defer; the explicit Unlock is what made the rule match.
func deferAndDropAroundSlowCall(mu *sync.Mutex, m map[string]int, key string, slow func()) error {
	mu.Lock()
	defer mu.Unlock()
	if m == nil {
		return nil
	}
	mu.Unlock()
	slow()
	mu.Lock()
	if key == "" {
		return nil
	}
	m[key] = 1
	return nil
}
