<?php
declare(strict_types=1);

// BUG: `== null` is true for 0, '', '0', [] and false. A legitimate empty
// string or a zero quantity is reported as "missing".
function missing_bad(?string $s): bool { return $s == null; }

// BUG: the negated spelling.
function present_bad(?int $n): bool { return $n != null; }

// BUG: null on the left. Both operand orders are separate patterns because
// the comparison node is not normalised.
function missing_bad_left(?string $s): bool { return null == $s; }
function present_bad_left(?int $n): bool { return null != $n; }

// BUG: `null` IN A PATTERN IS CASE-INSENSITIVE, so the two shouty spellings
// PHP allows are covered by the same four patterns and need no branches of
// their own. Measured, not assumed -- these two fixtures are the measurement.
function missing_bad_upper(?string $s): bool { return $s == NULL; }
function present_bad_mixed(?int $n): bool { return Null != $n; }
