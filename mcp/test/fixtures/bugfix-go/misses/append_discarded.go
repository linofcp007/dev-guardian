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
