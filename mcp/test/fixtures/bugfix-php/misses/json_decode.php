<?php
declare(strict_types=1);

// ONE CASE PER EXCLUSION IN THE RULE, and that is the point of the file: an
// exclusion with no fixture behind it reads DEAD under ablation and cannot be
// told apart from an exclusion that never worked. Every `pattern-not*` in
// `bugfix-php-null-safety-json-decode-deref` has an entry here.

// Correct: the NULLSAFE operator, straight off the call. `?->` and `->` are
// THE SAME AST NODE in PHP -- confirmed behaviourally and by --dump-ast -- so
// `pattern-not: $V?->$M` does not exclude this, it DELETES the rule. The only
// thing that works is a `pattern-not-regex: '\?->'`, a TEXT guard on an AST
// rule, and this is the case that proves it live.
function name_direct_nullsafe(string $body): string {
    return (string) (json_decode($body)?->name ?? '');
}

// Correct: the same through a local. The second branch carries its own copy of
// the text guard.
function name_of_nullsafe(string $body): string {
    $o = json_decode($body);
    return (string) ($o?->name ?? '');
}

// Correct: JSON_THROW_ON_ERROR straight off the call, both spellings of the
// dereference.
function name_direct_throwing(string $body): string {
    return (string) json_decode($body, false, 512, JSON_THROW_ON_ERROR)->name;
}
function id_direct_throwing(string $body): int {
    return (int) json_decode($body, true, 512, JSON_THROW_ON_ERROR)['id'];
}

// Correct: JSON_THROW_ON_ERROR, so a bad payload throws instead of returning
// null. Through a local this time.
function name_of_throwing(string $body): string {
    $o = json_decode($body, false, 512, JSON_THROW_ON_ERROR);
    return (string) $o->name;
}

// Correct: null checked, early RETURN.
function name_of(string $body): string {
    $o = json_decode($body);
    if ($o === null) { return ''; }
    return (string) $o->name;
}

// Correct: null checked, early THROW. A different statement from a return, and
// a separate exclusion.
function name_or_throw(string $body): string {
    $o = json_decode($body);
    if ($o === null) { throw new \RuntimeException('bad json'); }
    return (string) $o->name;
}

// Correct: is_object guard with an early return.
function name_if_object(string $body): string {
    $o = json_decode($body);
    if (!is_object($o)) { return ''; }
    return (string) $o->name;
}

// Correct: the positive form -- the dereference is INSIDE the guarded block.
function name_when_present(string $body): string {
    $o = json_decode($body);
    if ($o !== null) { return (string) $o->name; }
    return '';
}
function name_when_object(string $body): string {
    $o = json_decode($body);
    if (is_object($o)) { return (string) $o->name; }
    return '';
}

// Correct: isset() in a condition. THIS IS THE EXCLUSION THAT REAL CODE
// FORCED: without it the rule produced four false positives on WordPress 6.9,
// every one of them guarded by exactly this shape.
function has_error(string $body): bool {
    $o = json_decode($body);
    return isset($o->error);
}
function error_is_blank(string $body): bool {
    $o = json_decode($body);
    return empty($o->error);
}

// Correct: isset() guarding a block that dereferences.
function error_text(string $body): string {
    $o = json_decode($body);
    if (isset($o->error)) { return (string) $o->error; }
    return '';
}

// Correct: the negated isset with an early return, then the dereference.
function error_text_early(string $body): string {
    $o = json_decode($body);
    if (!isset($o->error)) { return ''; }
    return (string) $o->error;
}

// Correct: associative decode read with the null-coalescing operator. The
// rule's second branch only covers `$v->$m`, never `$v[...]` through a local:
// a subscript on null is a warning and a null read rather than a fatal, and
// the shape is far too common to flag. Stated so that nobody "completes" the
// rule by adding it.
function id_of(string $body): int {
    $a = json_decode($body, true);
    return (int) ($a['id'] ?? 0);
}

// Correct: not json_decode at all -- a property read on a decoded DTO.
final class Dto { public string $name = ''; }
function name_of_dto(Dto $d): string { return $d->name; }
