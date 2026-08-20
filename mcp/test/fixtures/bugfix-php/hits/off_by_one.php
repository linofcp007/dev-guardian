<?php
declare(strict_types=1);

// BUG: <= count() runs one past the end; $xs[count($xs)] is an undefined key.
function sum_bad(array $xs): int {
    $t = 0;
    for ($i = 0; $i <= count($xs); $i++) {
        $t += $xs[$i];
    }
    return $t;
}

// BUG: same, via sizeof(), which is an alias of count().
function sum_bad_sizeof(array $xs): int {
    $t = 0;
    for ($i = 0; $i <= sizeof($xs); $i++) { $t += $xs[$i]; }
    return $t;
}

// BUG: same, counting a property.
final class Bag { public array $items = []; }
function sum_bad_prop(Bag $b): int {
    $t = 0;
    for ($i = 0; $i <= count($b->items); $i++) { $t += $b->items[$i]; }
    return $t;
}

// BUG: strlen variant.
function chars_bad(string $t): array {
    $out = [];
    for ($i = 0; $i <= strlen($t); $i++) { $out[] = $t[$i]; }
    return $out;
}

// BUG: mb_strlen variant. Enumerated in the rule, so it needs a fixture: a
// branch with nothing behind it reads DEAD under ablation and cannot be told
// apart from a branch that never worked.
function mb_chars_bad(string $t): array {
    $out = [];
    for ($i = 0; $i <= mb_strlen($t); $i++) { $out[] = mb_substr($t, $i, 1); }
    return $out;
}

// BUG, COMMON SPELLING: count hoisted out of the condition. A rule that names
// count() in the condition misses this one.
function sum_bad_hoisted(array $xs): int {
    $t = 0; $n = count($xs);
    for ($i = 0; $i <= $n; $i++) { $t += $xs[$i]; }
    return $t;
}

// BUG: hoisted from strlen() rather than count(). The hoisted branch binds the
// function name to a metavariable and filters it with the same anchored regex
// as the direct branch, so all four names are reachable through both shapes.
function chars_bad_hoisted(string $s): array {
    $out = []; $len = strlen($s);
    for ($i = 0; $i <= $len; $i++) { $out[] = $s[$i]; }
    return $out;
}

// BUG, COMMON SPELLING: the loop variable is not named $i.
function sum_bad_other_var(array $rows): int {
    $t = 0;
    for ($k = 0; $k <= count($rows); $k++) { $t += $rows[$k]; }
    return $t;
}

// BUG: PRE-increment. `++$i` and `$i++` are different AST nodes, so the
// increment form is a dimension of this rule and not a spelling detail --
// the same mistake shape the `finally` dimension is for the catch rules.
function sum_bad_pre(array $xs): int {
    $t = 0;
    for ($i = 0; $i <= count($xs); ++$i) { $t += $xs[$i]; }
    return $t;
}

// BUG: pre-increment on the hoisted branch too.
function sum_bad_hoisted_pre(array $xs): int {
    $t = 0; $n = count($xs);
    for ($i = 0; $i <= $n; ++$i) { $t += $xs[$i]; }
    return $t;
}

// BUG: brace-less body. `for (...) ...` matches the braced body, the
// brace-less one AND the `for(): ... endfor;` alternative syntax; a pattern
// written `for (...) { ... }` matches only the first. Free recall, so both
// alternative bodies carry a fixture that would notice it being given up.
function sum_bad_braceless(array $xs): int {
    $t = 0;
    for ($i = 0; $i <= count($xs); $i++)
        $t += $xs[$i];
    return $t;
}

// NOT A BUG -- THE ONE KNOWN FALSE POSITIVE OF THIS RULE, kept here rather
// than in misses/ because it really does fire and pretending otherwise would
// make misses/ a lie. The array is deliberately allocated with count+1 slots,
// so the inclusive bound is right. The obvious tightening (require the body to
// index the counted array) was measured in the Java round and rejected: it
// does NOT kill this shape, and it loses a real bug where the out-of-range
// index is passed to a helper. It trades a false positive for a false
// negative, so it was not applied here either.
function fill_sentinel(array $xs): array {
    $out = array_fill(0, count($xs) + 1, 0);
    for ($i = 0; $i <= count($xs); $i++) {
        $out[$i] = $i;
    }
    return $out;
}

// BUG: the `endfor;` alternative syntax, which templates use everywhere.
function sum_bad_endfor(array $xs): int {
    $t = 0;
    for ($i = 0; $i <= count($xs); $i++):
        $t += $xs[$i];
    endfor;
    return $t;
}
