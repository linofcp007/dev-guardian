package misses

// sumInBounds is the DISCRIMINATING near-miss: flip the shipped rule's `<=`
// to `<` — the easiest typo to make in it — and this function fires. Proven
// by mutation during review, not assumed.
func sumInBounds(xs []int) int {
	sum := 0
	for i := 0; i < len(xs); i++ {
		sum += xs[i]
	}
	return sum
}

// sumRange is DOCUMENTARY, not discriminating, and that is worth saying out
// loud rather than leaving a reader to assume every near-miss carries the
// same weight. A `range` loop is a RangeStmt, a structurally different AST
// node from the ForStmt the rule matches, so no mutation of the C-style
// pattern — swapping the operator, the index, or the len() call — could ever
// make it fire. It records that rewriting the loop as a range is the safe
// fix; it proves nothing about the rule.
func sumRange(xs []int) int {
	sum := 0
	for _, x := range xs {
		sum += x
	}
	return sum
}

// sumToLenMinusOne is a second DISCRIMINATING near-miss, and it catches a
// mutation sumInBounds cannot. Measured, after a first version of this
// comment named a mutation it does NOT catch:
//
//   - widen the bound to `$I <= $BOUND` (any expression, not just len($XS))
//     -> this function fires, sumInBounds does not
//   - flip the operator to `$I < len($XS)`
//     -> sumInBounds fires, this function does not
//
// So the two cover different halves of the pattern, and neither is redundant.
// The loop itself is correct: `i <= len(xs)-1` deliberately stops one short.
func sumToLenMinusOne(xs []int) int {
	sum := 0
	for i := 0; i <= len(xs)-1; i++ {
		sum += xs[i]
	}
	return sum
}

// --- Written by the AUDITOR, and the reason the body requirement exists.
// --- Every function below is a CORRECT n+1 loop: the array being indexed has
// --- len(xs)+1 slots on purpose, so `i <= len(xs)` is exactly right and
// --- `i < len(xs)` would be the bug. The shipped Go rule required nothing of
// --- the body, so 4 of 4 fired at ERROR — every DP seed, prefix-sum array
// --- and split enumeration in a Go codebase. The Python rule had carried the
// --- fix since it shipped; it was never applied here.
// ---
// --- All four are DISCRIMINATING: delete `<... $XS[$I] ...>` from the body
// --- and all four fire.

func dpSeed(xs []int) []int {
	dp := make([]int, len(xs)+1)
	for i := 0; i <= len(xs); i++ {
		dp[i] = i
	}
	return dp
}

func prefixSums(xs []int) []int {
	ps := make([]int, len(xs)+1)
	for i := 0; i <= len(xs); i++ {
		if i > 0 {
			ps[i] = ps[i-1] + xs[i-1]
		}
	}
	return ps
}

func allSplits(xs []int) [][2][]int {
	out := make([][2][]int, 0, len(xs)+1)
	for i := 0; i <= len(xs); i++ {
		out = append(out, [2][]int{xs[:i], xs[i:]})
	}
	return out
}

func insertPositions(xs []int, v int) [][]int {
	var out [][]int
	for i := 0; i <= len(xs); i++ {
		ys := make([]int, 0, len(xs)+1)
		ys = append(ys, xs[:i]...)
		ys = append(ys, v)
		ys = append(ys, xs[i:]...)
		out = append(out, ys)
	}
	return out
}
