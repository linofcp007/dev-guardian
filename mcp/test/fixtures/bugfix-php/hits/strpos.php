<?php
declare(strict_types=1);

// BUG: strpos returns int 0 when the needle is at position 0, which is falsy.
// '@example.com' is reported as NOT containing '@'.
function has_at_bad(string $email): bool {
    if (strpos($email, '@')) { return true; }
    return false;
}

// BUG: the negated spelling, same defect.
function lacks_at_bad(string $email): bool {
    if (!strpos($email, '@')) { return true; }
    return false;
}

// BUG: returned directly as a bool.
function has_at_bad_return(string $email): bool {
    return (bool) strpos($email, '@');
}

// BUG: array_search returns key 0 for the first element, which is falsy.
function contains_bad(array $xs, string $needle): bool {
    if (array_search($needle, $xs)) { return true; }
    return false;
}

// BUG: stripos, same family.
function has_word_bad(string $hay): bool {
    if (stripos($hay, 'error')) { return true; }
    return false;
}

// BUG: loose == false. strpos(...) == false is TRUE for position 0 too.
function lacks_at_loose(string $email): bool {
    return strpos($email, '@') == false;
}

// BUG: the != false spelling of the same mistake.
function has_at_loose(string $email): bool {
    return strpos($email, '@') != false;
}

// BUG: == true. strpos() never returns true, so this is only ever "the needle
// is somewhere after position 0", which is not what it reads as.
function has_at_true(string $email): bool {
    return strpos($email, '@') == true;
}

// BUG: ternary condition.
function first_or_bad(string $email): string {
    return strpos($email, '@') ? 'yes' : 'no';
}

// BUG: while condition. Position 0 ends the loop one iteration early.
function trim_prefix_bad(string $s, string $sep): string {
    while (strpos($s, $sep)) { $s = substr($s, 1); }
    return $s;
}

// NOT REACHABLE, and said here rather than left out: the store-then-test
// spelling. The rule matches the CALL in a boolean position; once the result
// is bound to a local, the boolean position holds a variable and there is no
// call left to name. This is 1 of the 8 spellings and the only one missed.
function has_at_bad_via_var(string $email): bool {
    $at = strpos($email, '@');
    if ($at) { return true; }
    return false;
}
