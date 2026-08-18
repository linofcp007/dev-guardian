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
