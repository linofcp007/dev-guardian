package hits

import (
	"sync"
	"time"
)

func writeUnlockedOnHappyPathOnly(mu *sync.Mutex, m map[string]int, key string) error {
	mu.Lock()
	if key == "" {
		return nil
	}
	m[key] = 1
	mu.Unlock()
	return nil
}

// One early return releases the lock, the other does not: only the second
// is the bug, and it is the one reported.
func oneReturnForgets(mu *sync.Mutex, m map[string]int, key string) error {
	mu.Lock()
	if key == "" {
		mu.Unlock()
		return nil
	}
	if key == "skip" {
		return nil
	}
	m[key] = 1
	mu.Unlock()
	return nil
}

// A deferred Unlock of ANOTHER lock releases nothing here: the defer
// exclusion binds the same `$MU` as the Lock (review 3.7.0).
func deferOfAnotherLock(mu, other *sync.Mutex, m map[string]int, key string) error {
	mu.Lock()
	if key == "" {
		other.Lock()
		defer other.Unlock()
		return nil
	}
	m[key] = 1
	mu.Unlock()
	return nil
}

// goker's grpc3017 (runtime/testdata in the Go tree): the outer defer does
// not release the lock a callback takes for itself, and the callback returns
// holding it. The defer exclusion swallowed this one until the closure
// branches went in (review 3.7.0).
func callbackLocksUnderDefer(mu *sync.Mutex, m map[string]int, d time.Duration) {
	mu.Lock()
	defer mu.Unlock()
	time.AfterFunc(d, func() {
		mu.Lock()
		if m == nil {
			return
		}
		m["fired"] = 1
		mu.Unlock()
	})
}

func callbackRLocksUnderDefer(mu *sync.RWMutex, m map[string]int, d time.Duration) {
	mu.RLock()
	defer mu.RUnlock()
	time.AfterFunc(d, func() {
		mu.RLock()
		if m == nil {
			return
		}
		_ = m["fired"]
		mu.RUnlock()
	})
}
