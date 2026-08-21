package main

// registry is a settings cache, not a router. Its accessors collide with
// every Go HTTP framework's verb methods, which is the whole point of it.
type registry struct{}

// GET is the original screaming-case accessor, kept for the old call sites.
func (r registry) GET(k string, v any) {}

// Get replaced it: a lookup that falls back to the value it is handed.
func (r registry) Get(k string, fallback any) any { return fallback }

// keyspace is one namespace inside the registry, read without a fallback.
type keyspace struct{}

// Get reads a single key.
func (s keyspace) Get(k string) any { return nil }

func run(tenant string, defaultEntry any) {
	var reg registry
	var keys keyspace

	// F30 a non-HTTP type with a GET method
	reg.GET("/cache/key", nil)

	// F31 the same collision in TitleCase, read with ONE argument. Exercises
	//     guardian-route-go-chi's `pattern-not: $R.$METHOD($PATH)`: F30 is
	//     screaming-case, so the gin rule absorbs it and none of chi's own
	//     guards is ever reached.
	_ = keys.Get("/cache/one-arg")

	// F32 a nil fallback. Exercises guardian-route-go-chi's
	//     `pattern-not: $R.$METHOD($PATH, nil)`, the TitleCase counterpart of
	//     the guard F30 exercises on the gin rule.
	_ = reg.Get("/cache/key", nil)

	// F33 a computed key. Exercises guardian-route-go-chi's $PATH
	//     string-literal regex. The fallback is deliberately NOT nil: with
	//     nil there F32's guard would exclude the line first and the regex
	//     would never decide anything.
	cacheKey := "/cache/" + tenant
	_ = reg.Get(cacheKey, defaultEntry)
}
