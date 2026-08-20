<?php
declare(strict_types=1);

// Correct: strict less-than against count().
function sum_all(array $xs): int {
    $t = 0;
    for ($i = 0; $i < count($xs); $i++) {
        $t += $xs[$i];
    }
    return $t;
}

// THE SENTINEL ARRAY IS NOT IN THIS FILE, and that is deliberate. An
// inclusive loop over an array deliberately allocated with count+1 slots is
// correct code that this rule DOES flag -- a known, accepted false positive.
// It lives in hits/off_by_one.php, annotated, because this file is the
// specification of what the rule must be silent on: anything in here that
// fires means the rule is wrong, and a case we have decided to keep flagging
// would turn that promise into a lie.

// Correct: inclusive loop over a domain object's own "length". THIS IS THE
// JAVA/C# DEFECT REPRODUCED ON PURPOSE. In both of those packs a receiver
// with a `.Count`/`.length` member forced an enumerated `metavariable-type`
// list to keep the rule off domain objects. In PHP it cannot arise: `count()`
// is a GLOBAL FUNCTION, and `$s->count()` is a method call, a different node
// that `count($a)` does not match. Measured on exactly this class, carrying
// BOTH a `->length` property and a `->count()` method inside `<=` loops: the
// rule is silent on both. No type list is needed and none is present.
final class Segment {
    public function __construct(public readonly int $length) {}
    public function count(): int { return $this->length; }
}
function stakes(Segment $s): array {
    $out = [];
    for ($i = 0; $i <= $s->length; $i++) { $out[] = $i; }
    for ($j = 0; $j <= $s->count(); $j++) { $out[] = $j; }
    return $out;
}

// Correct: the static-method spelling of the same thing.
final class Ruler {
    public static function count(array $xs): int { return \count($xs) - 1; }
}
function marks(array $xs): array {
    $out = [];
    for ($i = 0; $i <= Ruler::count($xs); $i++) { $out[] = $i; }
    return $out;
}

// Correct: a domain function that returns the LAST VALID INDEX, so <= is
// right. This is what the function-name filter on the rule is for: without
// it, any `<= f($x)` in a for-header would be flagged.
function last_index(array $xs): int { return count($xs) - 1; }
function sum_to_last(array $xs): int {
    $t = 0;
    for ($i = 0; $i <= last_index($xs); $i++) { $t += $xs[$i]; }
    return $t;
}

// Correct: counting down to zero inclusive.
function reverse_all(array $xs): array {
    $out = [];
    for ($i = count($xs) - 1; $i >= 0; $i--) { $out[] = $xs[$i]; }
    return $out;
}

// Correct: <= against something that is not a count at all.
function repeat_n(int $times): string {
    $s = '';
    for ($i = 0; $i <= $times; $i++) { $s .= 'x'; }
    return $s;
}

// Correct: strlen with strict less-than.
function chars(string $t): array {
    $out = [];
    for ($i = 0; $i < strlen($t); $i++) { $out[] = $t[$i]; }
    return $out;
}

// Correct: <= count() - 1 is the same as < count().
function sum_minus_one(array $xs): int {
    $t = 0;
    for ($i = 0; $i <= count($xs) - 1; $i++) { $t += $xs[$i]; }
    return $t;
}

// Correct: the hoisted branch requires the hoisted variable to come from a
// counting builtin. A bound hoisted from arithmetic is not this bug.
function grid(int $rows): array {
    $out = [];
    $n = $rows - 1;
    for ($i = 0; $i <= $n; $i++) { $out[] = $i; }
    return $out;
}

// Correct: hoisted from a DOMAIN function that returns the last valid index.
// The hoisted branch carries its own copy of the function-name filter, and
// this is the case that proves it: without it, any hoisted `$n = f($x)`
// followed by an inclusive loop would be flagged.
function sum_to_last_hoisted(array $xs): int {
    $t = 0; $n = last_index($xs);
    for ($i = 0; $i <= $n; $i++) { $t += $xs[$i]; }
    return $t;
}
