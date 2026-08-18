package hits

import "net/http"

func fetchLeaking(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	_ = resp.StatusCode
	return nil
}
