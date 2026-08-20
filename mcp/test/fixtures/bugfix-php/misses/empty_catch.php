<?php
declare(strict_types=1);

final class Handled {
    private array $log = [];

    // Correct: logged.
    public function a(string $s): void {
        try { $this->risky($s); }
        catch (\RuntimeException $e) { $this->log[] = $e->getMessage(); }
    }

    // Correct: rethrown, wrapped.
    public function b(string $s): void {
        try { $this->risky($s); }
        catch (\RuntimeException $e) { throw new \LogicException('b', 0, $e); }
    }

    // Correct: handled by falling back.
    public function c(string $s): string {
        try { $this->risky($s); return 'ok'; }
        catch (\RuntimeException $e) { return 'fallback'; }
    }

    // Correct: deliberate silence, DECLARED IN THE NAME. This is the rule's
    // whole escape hatch, and it is a declaration of intent rather than a
    // guard -- the rule reads it directly instead of having to infer it.
    public function d(string $s): void {
        try { $this->risky($s); }
        catch (\RuntimeException $ignored) { }
    }

    // Correct: the same, WITH A FINALLY. The naming exemption has to be
    // carried by both try shapes, because `try{}catch(){}` and
    // `try{}catch(){}finally{}` are disjoint AST nodes -- neither contains the
    // other -- so the exemption written for one does not reach the other.
    // A rule that enumerates both shapes but exempts in only one flags this.
    public function e(string $s): void {
        try { $this->risky($s); }
        catch (\RuntimeException $ignored) { }
        finally { $this->log[] = 'done'; }
    }

    // Correct: the other two spellings of the same declaration.
    public function e2(string $s): void {
        try { $this->risky($s); }
        catch (\RuntimeException $ignore) { }
    }
    public function e3(string $s): void {
        try { $this->risky($s); }
        catch (\RuntimeException $expected) { }
        finally { $this->log[] = 'done'; }
    }

    // Correct: try/finally with NO catch and an empty finally is not a
    // swallowed exception -- the exception still propagates.
    public function f(string $s): void {
        try { $this->risky($s); }
        finally { }
    }

    // Correct: the catch body is not empty, it is a no-op assignment.
    public function g(string $s): bool {
        $ok = true;
        try { $this->risky($s); }
        catch (\RuntimeException $e) { $ok = false; }
        return $ok;
    }

    private function risky(string $s): void {
        if ($s === '') { throw new \RuntimeException('empty'); }
    }
}
