package misses

import "time"

func tickStopping() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		return
	}
}

// --- Written by the AUDITOR. Ownership transfer and the two spellings of
// --- "stopped that are not `defer t.Stop()`". All three fired.
// --- DISCRIMINATING: delete the matching exclusion and each one fires.

// The constructor hands the ticker to the caller, who stops it.
func newTicker(d time.Duration) *time.Ticker {
	t := time.NewTicker(d)
	return t
}

func tickCloseInClosure() {
	t := time.NewTicker(time.Second)
	defer func() { t.Stop() }()
	<-t.C
}

func tickStopExplicit() {
	t := time.NewTicker(time.Second)
	<-t.C
	t.Stop()
}
