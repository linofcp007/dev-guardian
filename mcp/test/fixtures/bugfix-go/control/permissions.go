package control

import "os"

// Exists only to trip p/r2c-bug-scan's own `incorrect-default-permission`
// rule, proving that pack is live for Go. None of our rules fire here, and
// this directory is not part of the hits/misses fixture pairs.
func widenPermissions(path string) error {
	return os.Chmod(path, 0777)
}
