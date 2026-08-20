package misses

import (
	"os"
	"strings"
	"sync"
	"unicode/utf8"
)

func readCheckingError(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func mapLookupOk(m map[string]int) int {
	v, _ := m["k"]
	return v
}

func channelRecvOk(ch chan int) int {
	v, _ := <-ch
	return v
}

func typeAssertOk(x interface{}) string {
	s, _ := x.(string)
	return s
}

// --- Written by the AUDITOR, not by the rule's author. Every function below
// --- is correct, idiomatic Go in which the SECOND return value is not an
// --- error at all: a bool or an int. The shipped rule reported all of them
// --- at ERROR, and `sync.Map.Load` alone made it fire across most
// --- concurrent Go. Each is DISCRIMINATING: delete its deny-list clause and
// --- the function fires.

func syncMapLoad(m *sync.Map, k string) any {
	v, _ := m.Load(k) // (any, bool)
	return v
}

func syncMapLoadAndDelete(m *sync.Map, k string) any {
	v, _ := m.LoadAndDelete(k) // (any, bool)
	return v
}

func syncMapLoadOrStore(m *sync.Map, k string, v any) any {
	got, _ := m.LoadOrStore(k, v) // (any, bool)
	return got
}

func stringsCut(s string) string {
	before, _, _ := strings.Cut(s, "=") // three values; not matched at all
	return before
}

func stringsCutPrefix(s string) string {
	after, _ := strings.CutPrefix(s, "prefix-") // (string, bool)
	return after
}

func stringsCutSuffix(s string) string {
	before, _ := strings.CutSuffix(s, "-suffix") // (string, bool)
	return before
}

func decodeRune(b []byte) rune {
	r, _ := utf8.DecodeRune(b) // (rune, int)
	return r
}

func decodeRuneInString(s string) rune {
	r, _ := utf8.DecodeRuneInString(s) // (rune, int)
	return r
}

func decodeLastRune(b []byte) rune {
	r, _ := utf8.DecodeLastRune(b) // (rune, int)
	return r
}

func decodeLastRuneInString(s string) rune {
	r, _ := utf8.DecodeLastRuneInString(s) // (rune, int)
	return r
}

// The ASSIGNMENT spelling of the same thing, which is also the only spelling
// the rule now carries: the `:=` branch that used to sit beside it matched
// exactly the same set and was deleted as dead.
func syncMapLoadReassign(m *sync.Map, k string) any {
	var v any
	v, _ = m.Load(k)
	return v
}
