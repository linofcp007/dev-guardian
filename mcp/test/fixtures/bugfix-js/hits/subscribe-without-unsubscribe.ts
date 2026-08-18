import { useEffect } from 'react';

interface Subscription {
  unsubscribe(): void;
}
interface Observable {
  subscribe(cb: () => void): Subscription;
}

export function Watcher(source: Observable, onNext: () => void): void {
  useEffect(() => {
    source.subscribe(onNext);
  }, []);
}
