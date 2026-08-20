<?php
declare(strict_types=1);

// BUG: TOCTOU. Between file_exists() and unlink() another request can delete
// the file, and unlink() then emits a warning and returns false.
function drop_bad(string $f): void {
    if (file_exists($f)) {
        unlink($f);
    }
}

// BUG: TOCTOU. Two concurrent workers both see !is_dir and both call mkdir;
// the loser gets "File exists" and mkdir returns false, unchecked.
function ensure_dir_bad(string $d): void {
    if (!is_dir($d)) {
        mkdir($d, 0777, true);
    }
}

// BUG: TOCTOU on the create side. Both workers see !file_exists and both
// write; one write is lost.
function seed_bad(string $f): void {
    if (!file_exists($f)) {
        file_put_contents($f, '{}');
    }
}

// BUG: is_writable then fopen -- the permission can change in between.
function append_bad(string $f, string $line): void {
    if (is_writable($f)) {
        $h = fopen($f, 'ab');
        fwrite($h, $line);
        fclose($h);
    }
}

// BUG: the same, with the handle not bound to a local. ONE branch covers both
// spellings and the second one was measured to add nothing: the statement
// ellipsis `{ ... fopen($F, $MODE); ... }` finds the call inside the
// assignment above as well, so the `$H = fopen(...)` branch the probe carried
// was dead weight and is not in the shipped rule.
function touch_bad(string $f): void {
    if (is_writable($f)) {
        fopen($f, 'ab');
    }
}
