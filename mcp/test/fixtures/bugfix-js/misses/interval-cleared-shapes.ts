/**
 * WRITTEN BY THE AUDITOR (probes/p13_interval.ts). Every function here
 * creates an interval and clears it, and every one of them fired: the two
 * exclusions the rule shipped with recognised a `function` declaration and a
 * `useEffect`, so the discriminator was the shape of the CONTAINER rather
 * than whether the timer was actually cleared. The byte-identical body
 * inside a `function` declaration was correctly silent — isolated as the
 * iso/i1.ts [C]/[C'] pair.
 *
 * Silent now because the container clauses cover arrow functions as well as
 * declarations; delete the arrow clause and the first four fire, delete the
 * declaration clause and the last two do.
 */

import { useEffect } from 'react';
declare function onMount(f: () => (() => void) | void): void;
declare function tick(): void;

// Svelte's canonical onMount idiom: an arrow callback returning a cleanup.
export function Svelte(): void {
  onMount(() => {
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  });
}

// Plain arrow that starts a timer and returns its own stopper.
export const startTimer = (): (() => void) => {
  const t = setInterval(tick, 1000);
  return () => clearInterval(t);
};

// Arrow that clears inline, two lines later.
export const clearsInline = (): void => {
  const t = setInterval(tick, 1000);
  clearInterval(t);
};

// useEffect with a block-bodied cleanup, written as an arrow component.
export const CorrectEffect = (): void => {
  useEffect(() => {
    const t = setInterval(tick, 1000);
    return () => {
      clearInterval(t);
    };
  }, []);
};

// Class method — `function $F(...)` shape, per Semgrep's generic matcher.
export class Poller {
  start(): void {
    const t = setInterval(tick, 1000);
    clearInterval(t);
  }
}

// Object-literal method, same shape.
export const objPoller = {
  run(): void {
    const t = setInterval(tick, 1000);
    clearInterval(t);
  },
};
