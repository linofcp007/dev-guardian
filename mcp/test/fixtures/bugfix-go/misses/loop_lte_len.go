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
