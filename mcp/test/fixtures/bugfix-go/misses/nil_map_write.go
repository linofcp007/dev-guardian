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
