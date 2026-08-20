package misses

import (
	"io"
	"net/http"
)

func fetchClosing(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// --- Written by the AUDITOR. Three correct closes that the shipped rule
// --- reported at ERROR, one per shape it did not know. Each is
// --- DISCRIMINATING: delete the matching exclusion and it fires.

// The errcheck-safe form: closing inside a closure is how you close AND
// handle the close error.
func closeInClosure(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, err = io.ReadAll(resp.Body)
	return err
}

func closeInClosureChecked(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer func() { resp.Body.Close() }()
	return nil
}

// Explicit, non-deferred close at the end of a short function.
func closeExplicitly(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	return b, err
}

// Closed via a helper that takes the closer.
func closeViaHelper(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer closeQuietly(resp.Body)
	return nil
}

func closeQuietly(c io.Closer) { _ = c.Close() }

// Ownership transfer: the response is handed to the caller, who closes it.
// Closing here would be the bug.
func fetchForCaller(c *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// The dominant real-world spelling, closed properly. It is silent because of
// the close, NOT because the rule cannot see `Do` — that was the shipped
// rule's blind spot and it is now a hit fixture.
func viaClientDoClosed(c *http.Client, req *http.Request) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
