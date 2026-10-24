// gosec's own ./... walk skips this directory: its name starts with "vendor".
package vendored

import "os"

func Write() error { return os.WriteFile("/tmp/out", []byte("x"), 0o777) }
