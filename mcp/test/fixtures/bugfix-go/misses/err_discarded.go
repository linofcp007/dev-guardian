package misses

import "os"

func readCheckingError(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func mapLookupOk(m map[string]int) int {
	v, _ := m["k"]
	return v
}

func channelRecvOk(ch chan int) int {
	v, _ := <-ch
	return v
}

func typeAssertOk(x interface{}) string {
	s, _ := x.(string)
	return s
}
