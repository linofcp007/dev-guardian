package misses

import "os"

func handleError(path string) error {
	err := os.Remove(path)
	if err != nil {
		return err
	}
	return nil
}

// --- Written by the AUDITOR. `$ERR` bound ANY identifier, so an empty body
// --- on a nil-check of something that is not an error fired at ERROR. The
// --- metavariable-regex on the name is what makes this silent, and this
// --- function is DISCRIMINATING: delete the regex and it fires.
func emptyNonErrBlock(p *os.File) {
	if p != nil {
	}
}
