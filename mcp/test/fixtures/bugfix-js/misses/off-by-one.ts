export function correct(items: number[]): void {
  for (let i = 0; i < items.length; i++) { console.log(items[i]); }
}
export function writesToLength(items: number[]): void {
  items[items.length] = 4;                          // appending, legitimate
}
