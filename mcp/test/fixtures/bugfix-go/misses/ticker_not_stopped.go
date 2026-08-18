package misses

import "time"

func tickStopping() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		return
	}
}
