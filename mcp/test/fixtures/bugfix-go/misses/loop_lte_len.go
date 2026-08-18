package misses

func sumInBounds(xs []int) int {
	sum := 0
	for i := 0; i < len(xs); i++ {
		sum += xs[i]
	}
	return sum
}

func sumRange(xs []int) int {
	sum := 0
	for _, x := range xs {
		sum += x
	}
	return sum
}
