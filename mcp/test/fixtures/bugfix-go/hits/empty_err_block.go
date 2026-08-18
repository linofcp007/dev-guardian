package hits

import "os"

func swallowError(path string) {
	err := os.Remove(path)
	if err != nil {
	}
}
