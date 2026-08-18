package hits

import "time"

func tickLeaking() {
	t := time.NewTicker(time.Second)
	for range t.C {
		return
	}
}
