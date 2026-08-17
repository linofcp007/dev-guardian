export function startPolling(tick: () => void): void {
  const t = setInterval(tick, 1000);
}
