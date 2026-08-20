<?php
declare(strict_types=1);

/**
 * EVERY BUG IN hits/, REWRITTEN WITH THE FIX ITS OWN MESSAGE PRESCRIBES.
 *
 * The whole pack is run over this file and asserted to produce ZERO findings.
 * That is a stronger check than running each rule against its own fixes, and
 * the difference is not theoretical: the `error-suppression-operator`
 * candidate passed every per-rule check in the probe and was killed HERE. The
 * toctou rule's message prescribes "act first and inspect the return value",
 * whose idiomatic PHP is `@mkdir(...)` / `@unlink(...)`, so that candidate
 * fired three times on another rule's prescribed fix.
 *
 * ONE RULE FIRING ON ANOTHER RULE'S PRESCRIBED FIX IS NOT A TUNING PROBLEM,
 * and no per-rule check can see it. This file is where it becomes visible.
 */
final class Fixed
{
    /** @var list<string> */
    private array $log = [];

    // empty-catch -> "log it, handle it, or rethrow; if the silence is
    // deliberate, declare it in the name".
    public function logged(string $s): void
    {
        try { $this->risky($s); }
        catch (\RuntimeException $e) { $this->log[] = $e->getMessage(); }
    }

    public function rethrown(string $s): void
    {
        try { $this->risky($s); }
        catch (\RuntimeException $e) { throw new \LogicException('wrapped', 0, $e); }
    }

    public function declared(string $s): void
    {
        try { $this->risky($s); }
        catch (\RuntimeException $ignored) { }
    }

    public function declaredWithFinally(string $s): void
    {
        try { $this->risky($s); }
        catch (\RuntimeException $ignored) { }
        finally { $this->log[] = 'done'; }
    }

    private function risky(string $s): void
    {
        if ($s === '') { throw new \RuntimeException('empty'); }
    }
}

// off-by-one -> "you probably meant $i < count($a)".
function sum(array $xs): int {
    $t = 0;
    for ($i = 0; $i < count($xs); $i++) { $t += (int) $xs[$i]; }
    return $t;
}
function sum_hoisted(array $xs): int {
    $t = 0; $n = count($xs);
    for ($i = 0; $i < $n; $i++) { $t += (int) $xs[$i]; }
    return $t;
}
function chars(string $s): array {
    $out = [];
    for ($i = 0; $i < strlen($s); ++$i) { $out[] = $s[$i]; }
    return $out;
}
function mb_chars(string $s): array {
    $out = [];
    for ($i = 0; $i < mb_strlen($s); $i++) { $out[] = mb_substr($s, $i, 1); }
    return $out;
}
function sum_sizeof(array $xs): int {
    $t = 0;
    for ($k = 0; $k < sizeof($xs); $k++) { $t += (int) $xs[$k]; }
    return $t;
}
// The sentinel case, whose correct form the rule flags anyway, is rewritten
// here the way its message suggests when the inclusive bound really is meant:
// count the slots explicitly rather than adding one to a bound.
function fill_sentinel(array $xs): array {
    $slots = count($xs) + 1;
    $out = array_fill(0, $slots, 0);
    for ($i = 0; $i < $slots; $i++) { $out[$i] = $i; }
    return $out;
}

// strpos-truthiness -> "compare with !== false (or === false)".
function has_at(string $e): bool { return strpos($e, '@') !== false; }
function lacks_at(string $e): bool { return strpos($e, '@') === false; }
function has_word(string $h): bool { return stripos($h, 'error') !== false; }
function contains(array $xs, string $n): bool { return array_search($n, $xs, true) !== false; }
function label(string $e): string { return strpos($e, '@') !== false ? 'yes' : 'no'; }
function trim_prefix(string $s, string $sep): string {
    while (strpos($s, $sep) !== false) { $s = substr($s, 1); }
    return $s;
}
function at_position(string $e): int {
    $at = strpos($e, '@');
    return $at === false ? -1 : $at;
}

// toctou -> "act first and inspect the return value". THE IDIOM FOR THAT IS
// THE ERROR-SUPPRESSION OPERATOR, which is why this block is the whole reason
// the check in this file is run with the WHOLE pack rather than per rule.
function drop(string $f): bool {
    return @unlink($f);
}
function ensure_dir(string $d): bool {
    if (@mkdir($d, 0777, true) === false && !is_dir($d)) { return false; }
    return true;
}
function seed(string $f): bool {
    $h = @fopen($f, 'xb');
    if ($h === false) { return false; }
    fwrite($h, '{}');
    fclose($h);
    return true;
}
function append(string $f, string $line): bool {
    $h = @fopen($f, 'ab');
    if ($h === false) { return false; }
    fwrite($h, $line);
    fclose($h);
    return true;
}

// json_decode -> "check for null, use ?->, or pass JSON_THROW_ON_ERROR".
function name_checked(string $b): string {
    $o = json_decode($b);
    if ($o === null) { return ''; }
    return (string) $o->name;
}
function name_nullsafe(string $b): string {
    return (string) (json_decode($b)?->name ?? '');
}
function name_throwing(string $b): string {
    $o = json_decode($b, false, 512, JSON_THROW_ON_ERROR);
    return (string) $o->name;
}
function id_coalesced(string $b): int {
    $a = json_decode($b, true);
    return (int) ($a['id'] ?? 0);
}
function items_checked(string $b): int {
    $o = json_decode($b);
    if (!is_object($o)) { return 0; }
    return count($o->items);
}

// loose-null -> "use === null (or !== null), or ?? for a default".
function missing(?string $s): bool { return $s === null; }
function present(?int $n): bool { return $n !== null; }
function or_default(?string $s): string { return $s ?? 'd'; }
