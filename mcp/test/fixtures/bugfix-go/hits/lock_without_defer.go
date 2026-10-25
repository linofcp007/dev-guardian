package hits

import "sync"

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
