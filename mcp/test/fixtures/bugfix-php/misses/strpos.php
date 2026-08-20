<?php
declare(strict_types=1);

// Correct: strict comparison against false.
function has_at(string $email): bool {
    return strpos($email, '@') !== false;
}

// Correct: the negated strict comparison.
function lacks_at(string $email): bool {
    return strpos($email, '@') === false;
}

// THE THREE BELOW ARE WHY THE FUNCTION-NAME FILTER EXISTS. Every pattern in
// this rule is written over `$F(...)` in a boolean position, so without the
// anchored name regex it fires on every correct call in this file. Measured:
// three false positives, one per function.

// Correct: str_contains (PHP 8) returns a real bool.
function has_at8(string $email): bool {
    if (str_contains($email, '@')) { return true; }
    return false;
}

// Correct: a function that really does return a bool, used in a condition.
function is_prefixed(string $s): bool {
    if (str_starts_with($s, 'wp_')) { return true; }
    return false;
}

// Correct: preg_match returns 1/0/false; 0 means "no match", and using it in a
// condition is the documented idiom because position 0 is not a return value.
function looks_numeric(string $s): bool {
    if (preg_match('/^\d+$/', $s)) { return true; }
    return false;
}

// Correct: the position is USED as a number, not as a truth value.
function domain(string $email): string {
    $at = strpos($email, '@');
    if ($at === false) { return ''; }
    return substr($email, $at + 1);
}

// Correct: array_search compared strictly.
function index_of(array $xs, string $needle): int {
    $i = array_search($needle, $xs, true);
    return $i === false ? -1 : (int) $i;
}

// Correct: the ternary spelling, compared strictly.
function label(string $email): string {
    return strpos($email, '@') !== false ? 'yes' : 'no';
}

// Correct: a while loop over the position, compared strictly, advancing past
// each hit. The rule has a `while` branch and this is the shape it must not
// reach.
function count_at(string $s): int {
    $n = 0; $at = 0;
    while (($at = strpos($s, '@', $at)) !== false) { $n++; $at++; }
    return $n;
}
