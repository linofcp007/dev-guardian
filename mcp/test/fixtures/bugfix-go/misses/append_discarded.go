package misses

func growAssigning(xs []int) []int {
	xs = append(xs, 1)
	return xs
}

func growDeclaring(xs []int) []int {
	ys := append(xs, 1)
	return ys
}

func growReturning(xs []int) []int {
	return append(xs, 1)
}

func growPassing(xs []int) {
	println(len(append(xs, 1)))
}

func growReturningMultiFirst(xs []int) ([]int, error) {
	return append(xs, 1), nil
}

func growReturningMultiSecond(xs []int) (int, []int) {
	return 0, append(xs, 1)
}

func growInSliceLiteral(xs []int) [][]int {
	return [][]int{append(xs, 1)}
}

func growInMapLiteral(xs []int) map[string][]int {
	return map[string][]int{"k": append(xs, 1)}
}
