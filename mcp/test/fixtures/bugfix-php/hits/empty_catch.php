<?php
declare(strict_types=1);

final class Swallowed {
    // BUG: swallowed, named variable.
    public function a(string $s): void {
        try { $this->risky($s); }
        catch (\RuntimeException $e) { }
    }

    // NOT REACHABLE, AND SAID HERE RATHER THAN LEFT OUT: the PHP 8
    // non-capturing catch. Every AST spelling of it fails to parse as a
    // pattern, so this rule cannot match it at all. It matters more than a
    // missing spelling usually would, because THIS is how modern PHP declares
    // deliberate silence -- so the gap is also a self-exemption, and what is
    // left is the capturing spelling that real code uses for the same intent.
    // A `pattern-regex` does find these, but cannot carry the naming
    // exemption, which is the only thing keeping this rule off correct code.
    public function b(string $s): void {
        try { $this->risky($s); }
        catch (\RuntimeException) { }
    }

    // BUG: swallowed, catch-all \Throwable.
    public function c(string $s): void {
        try { $this->risky($s); }
        catch (\Throwable $t) { }
    }

    // BUG: swallowed, with a finally after it. A try statement WITH a
    // finalizer is a different AST node from one without: neither pattern
    // contains the other, so both are enumerated. This exact hole shipped in
    // the Java pack and cost a separate fix round.
    public function d(string $s): void {
        try { $this->risky($s); }
        catch (\RuntimeException $e) { }
        finally { $this->touch(); }
    }

    // NOT REACHABLE: the non-capturing form with a finally, for the same
    // reason as b().
    public function e(string $s): void {
        try { $this->risky($s); }
        catch (\RuntimeException) { }
        finally { $this->touch(); }
    }

    // BUG: swallowed, union catch type (PHP 7.1+). Binding the type to a
    // metavariable is what makes this reachable: a pattern naming
    // `\RuntimeException` matches neither this nor c().
    public function f(string $s): void {
        try { $this->risky($s); }
        catch (\RuntimeException | \LogicException $e) { }
    }

    // BUG: two catch clauses, the first swallows, the second is fine.
    public function g(string $s): void {
        try { $this->risky($s); }
        catch (\RuntimeException $e) { }
        catch (\LogicException $e) { throw $e; }
    }

    // BUG: swallowed inside a loop -- the catch body only holds a comment.
    // Semgrep cannot read comments, which is exactly why this rule is WARNING
    // and not ERROR: all ten of its findings on WordPress 6.9 are deliberate
    // silences carrying an explanatory comment just like this one.
    public function h(array $items): void {
        foreach ($items as $i) {
            try { $this->risky((string) $i); }
            catch (\RuntimeException $e) {
                // nothing to do here
            }
        }
    }

    private function touch(): void { }
    private function risky(string $s): void {
        if ($s === '') { throw new \RuntimeException('empty'); }
    }
}
