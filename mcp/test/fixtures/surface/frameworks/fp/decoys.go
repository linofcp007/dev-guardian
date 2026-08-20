package main

type registry struct{}

func (r registry) GET(k string, v any) {}

// F30 a non-HTTP type with a GET method
func run() {
	var reg registry
	reg.GET("/cache/key", nil)
}
