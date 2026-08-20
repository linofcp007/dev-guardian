<?php
declare(strict_types=1);

// Correct: identity comparison against null.
function missing(?string $s): bool { return $s === null; }
function present(?int $n): bool { return $n !== null; }

// Correct: the null-coalescing operator.
function or_default(?string $s): string { return $s ?? 'd'; }

// Correct: is_null.
function missing2(?string $s): bool { return is_null($s); }

// Correct: loose == between two values where the juggling is intended, e.g.
// a numeric string from a form against an int id. The rule names `null` on
// one side, so an ordinary loose comparison is not this bug.
function same_id(string $formId, int $id): bool { return $formId == $id; }

// Correct: comparing against the string 'null', which is a value and not the
// null literal -- a JSON payload really can carry it.
function is_literal_null(string $s): bool { return $s == 'null'; }
