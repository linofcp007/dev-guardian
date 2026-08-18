export function appendAtLength(items: number[]): void {
  items[items.length] = 4;                          // append, not a read — Task 1's own
                                                      // misses/off-by-one.ts already carries
                                                      // this exact case; repeated here so this
                                                      // rule's own proof is self-contained.
}
export function readLastValid(items: number[]): number | undefined {
  return items[items.length - 1];                    // correct idiom: length - 1
}
