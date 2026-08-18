package hits

import "os"

func readIgnoringError(path string) []byte {
	data, _ := os.ReadFile(path)
	return data
}
