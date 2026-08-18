package misses

import "net/http"

func fetchClosing(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
