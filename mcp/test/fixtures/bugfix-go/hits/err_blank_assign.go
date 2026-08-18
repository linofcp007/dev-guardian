package hits

import "os"

func removeIgnoringError(path string) {
	_ = os.Remove(path)
}
