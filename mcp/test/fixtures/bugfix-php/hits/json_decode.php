<?php
declare(strict_types=1);

// BUG: json_decode returns null on malformed input; ->name is then an
// "Attempt to read property on null" and the value is null.
function name_of_bad(string $body): string {
    return (string) json_decode($body)->name;
}

// BUG: same, through a local.
function name_of_bad_var(string $body): string {
    $o = json_decode($body);
    return (string) $o->name;
}

// BUG: associative form, subscripted directly off the call.
function id_of_bad(string $body): int {
    return (int) json_decode($body, true)['id'];
}

// BUG: method call on the decoded value. `$v->$m` covers a method call as
// well as a property read.
function count_of_bad(string $body): int {
    $o = json_decode($body);
    return count($o->items);
}

// BUG: the guard is on a DIFFERENT variable. This one is here rather than in
// misses/ because of what ablation axis 2 measures -- removing an exclusion
// must not REVEAL a finding in hits/ -- and an exclusion that swallows a real
// bug is invisible unless the bug sits next to the guard shape it matches.
function name_of_wrong_guard(string $body, ?object $other): string {
    $o = json_decode($body);
    if ($other === null) { return ''; }
    return (string) $o->name;
}

// BUG: the isset() is on a different property than the one dereferenced, and
// isset() on a null base is false anyway -- so the read below is unguarded.
// The exclusion is deliberately keyed on the same variable, not the same
// property, so this still fires and proves the exclusion is not too wide.
function summary_bad(string $body): string {
    $o = json_decode($body);
    if (isset($o->error)) { return 'error'; }
    return (string) $o->title;
}
