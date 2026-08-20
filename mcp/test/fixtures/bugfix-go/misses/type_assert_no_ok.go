package misses

import "fmt"

func maybeString(v interface{}) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func switchPlain(v interface{}) string {
	switch v.(type) {
	case string:
		return "s"
	}
	return ""
}

func switchBound(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	}
	return ""
}

// --- Written by the AUDITOR. The assertion sits inside a type-switch arm
// --- that has ALREADY proven the dynamic type, so it cannot panic. The
// --- shipped rule fired at ERROR, and the rule file claimed the exclusion
// --- was unnecessary. It is necessary; what did not work was the spelling
// --- (`switch $V.(type) { ... }` is a Go syntax error as a pattern).
// --- DISCRIMINATING: delete the type-switch clause and this fires.
func afterTypeSwitch(v any) string {
	switch v.(type) {
	case fmt.Stringer:
		return v.(fmt.Stringer).String()
	}
	return ""
}

// The `, ok` form used as an if-statement initialiser, and the form that
// discards the value — the two spellings the surviving exclusion has to keep
// covering after its redundant twin was deleted.
func guardedInIf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func guardedDiscardValue(v any) bool {
	if _, ok := v.(fmt.Stringer); ok {
		return true
	}
	return false
}
