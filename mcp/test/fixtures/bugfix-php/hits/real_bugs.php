<?php
declare(strict_types=1);

/**
 * THE REAL-BUGS CORPUS -- one defect per rule, all six, written where the
 * defect would actually sit rather than as a minimal instantiation.
 *
 * Everything else in hits/ is one small example per rule, written by whoever
 * wrote the rule. That proves a rule FIRES, but it cannot prove an exclusion
 * added later did not eat a real bug, because a minimal fixture carries no
 * guard shapes for an exclusion to catch on. Every defect here is written
 * BESIDE the guard shape its rule's exclusions match -- inside a try, next to
 * an `isset()` on another property, next to a correct sibling loop -- so that
 * ablation axis 2 has something to reveal if an exclusion is one notch wide.
 *
 * Lines marked `// excluded:` are the near-misses deliberately placed beside
 * the bug. A reveal on one of THOSE under ablation is the clause working; a
 * reveal on a `// BUG:` line is the defect axis 2 exists for.
 */
final class FeedImporter
{
    private const CACHE_DIR = '/var/cache/feed';

    /** @var list<string> */
    private array $warnings = [];

    /**
     * BUG (race_condition-toctou-file): two workers importing at once both
     * see `!is_dir` and both call mkdir; the loser gets "File exists", mkdir
     * returns false, and nobody looks. Written next to the atomic idiom the
     * rule must NOT flag, which is also the fix its own message prescribes.
     */
    public function prepare(): void
    {
        if (!is_dir(self::CACHE_DIR)) {
            mkdir(self::CACHE_DIR, 0775, true);
        }
        // excluded: act-first-and-inspect. Idiomatic, atomic, and silent.
        if (@mkdir(self::CACHE_DIR . '/tmp', 0775, true) === false && !is_dir(self::CACHE_DIR . '/tmp')) {
            $this->warnings[] = 'tmp unavailable';
        }
    }

    /**
     * BUG (null_safety-json-decode-deref): a remote feed is not guaranteed to
     * be JSON. `json_decode` returns null, `->items` reads null, and `count()`
     * gets null. The `isset()` two lines up guards a DIFFERENT property, and
     * `isset()` on a null base is false anyway -- so it protects nothing here.
     * That is the near-miss the exclusion has to be narrow enough to keep:
     * the exclusion is keyed on the variable, not on the property.
     */
    public function itemCount(string $body): int
    {
        $feed = json_decode($body);
        // excluded: an isset() read of the SAME variable is guarded and silent.
        if (isset($feed->error)) {
            $this->warnings[] = 'feed reported an error';
        }
        return count($feed->items);
    }

    /**
     * BUG (off_by_one-loop-lte-count): the bound is hoisted, which is the
     * commonest spelling, and the last iteration reads `$rows[count($rows)]`
     * -- an undefined key, so `$row` is null and `$row['id']` warns twice.
     * The correct sibling loop right below is what an over-tightened rule
     * would take with it.
     */
    public function ids(array $rows): array
    {
        $out = [];
        $n = count($rows);
        for ($i = 0; $i <= $n; $i++) {
            $row = $rows[$i];
            $out[] = is_array($row) ? (string) $row['id'] : '';
        }
        // excluded: strict less-than over the same array, silent.
        for ($j = 0; $j < $n; $j++) {
            $out[] = 'seen';
        }
        return $out;
    }

    /**
     * BUG (edge_case-strpos-truthiness): a feed URL of the form
     * "?utm_source=..." has its '?' at position 0, and this reports it as
     * having no query string at all. Written beside the two correct forms the
     * function-name filter exists to protect.
     */
    public function hasQuery(string $url): bool
    {
        if (strpos($url, '?')) {
            return true;
        }
        // excluded: str_contains returns a real bool; preg_match's 0 means
        // "no match" and is not a position. Both correct, both silent.
        if (str_contains($url, '&') || preg_match('/#\w+$/', $url)) {
            return true;
        }
        return false;
    }

    /**
     * BUG (error_handling-empty-catch): the write failure is swallowed and the
     * caller is told the item was cached. The `finally` is what makes this the
     * interesting shape -- a try WITH a finalizer is a different AST node, and
     * a rule that enumerates only the plain try is blind to it.
     *
     * The catch below it is the naming exemption, in the same method, so an
     * exclusion that leaked across sibling statements would show up here.
     */
    public function cache(string $key, string $payload): bool
    {
        $path = self::CACHE_DIR . '/' . $key;
        try {
            $this->write($path, $payload);
        } catch (\RuntimeException $e) {
        } finally {
            $this->warnings[] = 'cache attempted';
        }
        // excluded: silence DECLARED IN THE NAME, so this one is intended.
        try {
            $this->write($path . '.stamp', (string) time());
        } catch (\RuntimeException $ignored) {
        }
        return true;
    }

    /**
     * BUG (null_safety-loose-null-compare): `== null` is true for the string
     * '0' and for the integer 0, so a legitimate etag of "0" is treated as
     * absent and the feed is refetched on every request. The strict comparison
     * one line down is the fix the message prescribes.
     */
    public function isStale(?string $etag, ?int $age): bool
    {
        if ($etag == null) {
            return true;
        }
        // excluded: identity comparison, silent.
        if ($age === null) {
            return true;
        }
        return $age > 3600;
    }

    private function write(string $path, string $payload): void
    {
        if (file_put_contents($path, $payload) === false) {
            throw new \RuntimeException('write failed');
        }
    }
}
