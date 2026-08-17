import { useEffect } from 'react';

export function startAndStopPolling(tick: () => void): void {
  const t = setInterval(tick, 1000);
  clearInterval(t);
}

export function PollingEffectExprCleanup(tick: () => void): void {
  useEffect(() => {
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);
}

export function PollingEffectBlockCleanup(tick: () => void): void {
  useEffect(() => {
    const t = setInterval(tick, 1000);
    return () => {
      clearInterval(t);
    };
  }, []);
}
