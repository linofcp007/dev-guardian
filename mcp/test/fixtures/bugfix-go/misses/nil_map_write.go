package misses

import "encoding/json"

func writeToMadeMap() map[string]int {
	m := make(map[string]int)
	m["k"] = 1
	return m
}

func writeToAssignedMap() map[string]int {
	var m map[string]int
	m = make(map[string]int)
	m["k"] = 1
	return m
}

func readFromNilMapIsFine() int {
	var m map[string]int
	return m["k"]
}

func writeAfterCtor() map[string]string {
	var cfg map[string]string
	cfg = defaults()
	cfg["x"] = "y"
	return cfg
}

func writeAfterAliasing(src map[string]string) map[string]string {
	var m map[string]string
	m = src
	m["k"] = "v"
	return m
}

func writeAfterLiteral() map[string]int {
	var m map[string]int
	m = map[string]int{}
	m["k"] = 1
	return m
}

func defaults() map[string]string { return map[string]string{} }

// --- Written by the AUDITOR. `json.Unmarshal(b, &m)` fills the map through
// --- a pointer, so the write afterwards is correct — and the shipped rule
// --- reported it at ERROR because it only understood re-ASSIGNMENT.
// --- DISCRIMINATING: delete the address-of clause and this fires.
func fromJSON(b []byte) (map[string]int, error) {
	var m map[string]int
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	m["seen"] = 1
	return m, nil
}

// Initialisation through a conditional, a switch, an explicit nil guard, and
// inside a loop body. All four are covered by the same re-assignment clause,
// and all four are what that clause exists for.
func lazyInit(cond bool) map[string]int {
	var m map[string]int
	if cond {
		m = make(map[string]int)
	} else {
		m = map[string]int{"d": 0}
	}
	m["k"] = 1
	return m
}

func guarded() map[string]int {
	var m map[string]int
	if m == nil {
		m = make(map[string]int)
	}
	m["k"] = 1
	return m
}

// The struct-field branch is new, and this is its near-miss: the map field is
// assigned before the write, so nothing is nil. DISCRIMINATING: delete the
// second branch's exclusion and this fires.
type config struct {
	Labels map[string]string
}

func structFieldInitialised() *config {
	c := &config{}
	c.Labels = map[string]string{}
	c.Labels["env"] = "prod"
	return c
}

// The same field, initialised in the literal itself. The `&$T{}` anchor
// requires an EMPTY literal, so this never matched.
func structFieldInLiteral() *config {
	c := &config{Labels: map[string]string{}}
	c.Labels["env"] = "prod"
	return c
}
