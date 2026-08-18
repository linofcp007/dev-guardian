package misses

func writeToMadeMap() map[string]int {
	m := make(map[string]int)
	m["k"] = 1
	return m
}

func writeToAssignedMap() map[string]int {
	var m map[string]int
	m = make(map[string]int)
	m["k"] = 1
	return m
}

func readFromNilMapIsFine() int {
	var m map[string]int
	return m["k"]
}

func writeAfterCtor() map[string]string {
	var cfg map[string]string
	cfg = defaults()
	cfg["x"] = "y"
	return cfg
}

func writeAfterAliasing(src map[string]string) map[string]string {
	var m map[string]string
	m = src
	m["k"] = "v"
	return m
}

func writeAfterLiteral() map[string]int {
	var m map[string]int
	m = map[string]int{}
	m["k"] = 1
	return m
}

func defaults() map[string]string { return map[string]string{} }
