package hits

func sumPastEnd(xs []int) int {
	sum := 0
	for i := 0; i <= len(xs); i++ {
		sum += xs[i]
	}
	return sum
}
