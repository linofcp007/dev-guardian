// Package hits: the REAL-BUGS CORPUS, written by the AUDITOR rather than by
// the rules' author, and the structural answer to how a wave of
// false-positive work can open a false-negative hole with a green suite.
//
// Everything else in hits/ is one minimal instantiation per rule, written by
// whoever wrote the rule. That proves a rule fires at all. It cannot prove
// that an exclusion added later did not eat a real bug, because a minimal hit
// fixture carries no guard shapes for an exclusion to catch on — and the
// near-miss fixtures only ever measure the direction the exclusion was
// written for.
//
// Every defect below is deliberately placed NEXT TO the guard shape its
// rule's exclusions match, so that widening any of those exclusions by one
// step turns this file red:
//
//   - a leaked response in the same function as a closed one
//   - a discarded error in the same function as a `sync.Map.Load`
//   - an unguarded assertion on a DIFFERENT variable inside a type switch
//   - a ticker leaked while a sibling ticker is stopped
//   - an early return past an RUnlock, which the shipped rule could not see
//     at all
//   - the five HTTP entry points that dominate real clients and that the
//     `http.Get`-only anchor missed entirely
//   - a discarded error beside the Close idiom and a builtin discard
//   - a genuine off-by-one beside a correct n+1 DP seed
//
// Every rule in the pack has at least one entry here. The Java pack stated
// three rules at zero as a decision; this one has none at zero, because
// after this round every Go rule carries guard exclusions and none of them
// is low-risk by construction any more.
package hits

import (
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

type respBox struct {
	Headers map[string]string
}

// bug 1: the dominant real-world spelling. `client.Do(req)` is what anything
// setting headers, timeouts or contexts uses, and the shipped rule was
// anchored to `http.Get` alone.
func leakViaClientDo(c *http.Client, req *http.Request) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_ = resp.StatusCode
	return nil
}

// bug 2.
func leakViaPost(url string, body io.Reader) error {
	resp, err := http.Post(url, "application/json", body)
	if err != nil {
		return err
	}
	_ = resp.StatusCode
	return nil
}

// bug 3.
func leakViaDefaultClient(url string) error {
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return err
	}
	_ = resp.StatusCode
	return nil
}

// bugs 3b and 3c: the remaining `http` package entry points. Ablation found
// both branches dead without a fixture behind them, and a branch nothing
// exercises can be deleted without a test moving — which is exactly how an
// anchor loses a spelling.
func leakViaPostForm(url string) error {
	resp, err := http.PostForm(url, nil)
	if err != nil {
		return err
	}
	_ = resp.StatusCode
	return nil
}

func leakViaHead(url string) error {
	resp, err := http.Head(url)
	if err != nil {
		return err
	}
	_ = resp.StatusCode
	return nil
}

// bug 4: a leak sitting beside a correct close in the SAME function. The
// close exclusions unify on the response variable; widen any of them to
// "there is a close somewhere" and this stops firing.
func leakBesideClose(url string, other string) error {
	good, err := http.Get(url)
	if err != nil {
		return err
	}
	defer good.Body.Close()
	bad, err := http.Get(other)
	if err != nil {
		return err
	}
	_ = bad.StatusCode
	return nil
}

// bug 5: a discarded error in the same function as a `sync.Map.Load`, whose
// second value really is a bool. The deny-list is per-callee; make it a
// per-function "this file talks to sync.Map" heuristic and this stops firing.
func discardBesideMapLoad(m *sync.Map, path string) []byte {
	_, _ = m.Load(path)
	data, _ := os.ReadFile(path)
	return data
}

// bug 6: an unguarded assertion on `w`, inside a type switch that proves
// nothing about `w` because it switches on `v`.
func assertOtherVarInTypeSwitch(v any, w any) string {
	switch v.(type) {
	case string:
		return w.(string)
	}
	return ""
}

// bug 7: an empty error branch whose variable is not spelled exactly `err`.
// The name filter must stay a substring test.
func emptyBranchNamedReadErr(path string) {
	readErr := os.Remove(path)
	if readErr != nil {
	}
}

// bug 8: a leaked ticker beside a stopped one. The stop exclusions unify on
// the ticker variable.
func tickerLeakBesideStop() {
	stopped := time.NewTicker(time.Second)
	defer stopped.Stop()
	leaked := time.NewTicker(time.Minute)
	<-leaked.C
}

// bug 9: an early return past `RUnlock`. `sync.RWMutex` read locks leak in
// exactly the same way and the shipped rule had no branch for them.
func rlockEarlyReturn(mu *sync.RWMutex, m map[string]int, key string) int {
	mu.RLock()
	if key == "" {
		return 0
	}
	v := m[key]
	mu.RUnlock()
	return v
}

// bug 10: the classic nil-map panic, which the `var $M map[$K]$V` anchor
// could not see: `&T{}` leaves every map field nil.
func structFieldNilMapWrite() *respBox {
	b := &respBox{}
	b.Headers["content-type"] = "application/json"
	return b
}

// bug 11: a discarded error beside the two shapes `err-blank-assign` now
// excludes — the Close idiom and a non-error builtin. The rule had NO corpus
// entry while carrying five exclusion clauses, which is exactly the profile
// the corpus exists for.
func discardBesideExcludedForms(f *os.File, path string) {
	_ = f.Close()                        // excluded: the Close idiom
	_ = copy(make([]byte, 1), []byte{2}) // excluded: builtin, no error
	_ = os.Remove(path)                  // fires: a real discarded error
}

// bug 12: a genuine off-by-one in the same function as a correct n+1 loop.
// The body requirement added in this round is what separates them, and
// without this the rule had no corpus entry at all.
func offByOneBesideDPSeed(xs []int) int {
	dp := make([]int, len(xs)+1)
	for i := 0; i <= len(xs); i++ {
		dp[i] = i // correct: dp has len(xs)+1 slots
	}
	sum := 0
	for i := 0; i <= len(xs); i++ {
		sum += xs[i] // BUG: indexes xs at len(xs)
	}
	return sum + dp[0]
}
