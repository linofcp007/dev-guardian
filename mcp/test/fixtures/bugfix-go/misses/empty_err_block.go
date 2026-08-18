package misses

import "os"

func handleError(path string) error {
	err := os.Remove(path)
	if err != nil {
		return err
	}
	return nil
}
