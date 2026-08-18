package misses

import "os"

func removeLoggingError(path string) {
	if err := os.Remove(path); err != nil {
		println(err.Error())
	}
}
