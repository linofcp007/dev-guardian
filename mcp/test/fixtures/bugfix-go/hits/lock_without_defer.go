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
