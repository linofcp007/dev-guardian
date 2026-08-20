<?php
declare(strict_types=1);

// Correct: act first, inspect the result. No window between check and use.
// This is also the fix this rule's own message prescribes, which is why the
// `@`-suppression candidate could not ship: it fired here.
function ensure_dir(string $d): bool {
    if (@mkdir($d, 0777, true) === false && !is_dir($d)) { return false; }
    return true;
}

// Correct: unlink and inspect the return value; no prior existence check.
function drop(string $f): bool {
    return @unlink($f);
}

// Correct: file_exists used for a REPORT, not as a guard for a mutation.
function describe(string $f): string {
    if (file_exists($f)) { return 'present'; }
    return 'absent';
}

// Correct: exclusive create, which is atomic at the OS level.
function claim(string $f): bool {
    $h = @fopen($f, 'xb');
    if ($h === false) { return false; }
    fclose($h);
    return true;
}

// Correct: is_dir guarding a READ, not a create.
function listing(string $d): array {
    if (is_dir($d)) { return scandir($d) ?: []; }
    return [];
}

// Correct: file_exists guarding a READ. The rule pairs a check with the
// MUTATION it races against; a read is not one.
function load(string $f): string {
    if (file_exists($f)) { return (string) file_get_contents($f); }
    return '';
}

// Correct: is_writable guarding a read-mode fopen. Reading does not race with
// the writability check, which is why the rule names the mutating shapes and
// not `fopen` in general.
function head(string $f): string {
    if (is_writable($f)) {
        $h = fopen($f, 'rb');
        if ($h === false) { return ''; }
        $line = (string) fgets($h);
        fclose($h);
        return $line;
    }
    return '';
}
