package misses

import (
	"fmt"
	"io"
	"os"
)

func removeLoggingError(path string) {
	if err := os.Remove(path); err != nil {
		println(err.Error())
	}
}

// --- Written by the AUDITOR. `var _ io.Writer = newWriter()` is the
// --- compile-time interface-satisfaction assertion, a universal Go idiom
// --- that discards no error because nothing runs; `copy`, `len` and `cap`
// --- are builtins with no error to discard. All four fired.

var _ = fmt.Stringer(nil)

var _ io.Writer = newWriter()

func newWriter() *os.File { return nil }

func discardCopyCount(dst, src []int) {
	_ = copy(dst, src) // int
}

func discardLen(xs []int) {
	_ = len(xs) // int
}

func discardCap(xs []int) {
	_ = cap(xs) // int
}
