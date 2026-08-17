import { useEffect } from 'react';

export function ResizeWatcher(onResize: () => void): void {
  useEffect(() => {
    window.addEventListener('resize', onResize);
  }, []);
}
