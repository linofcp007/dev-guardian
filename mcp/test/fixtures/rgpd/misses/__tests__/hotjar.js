// A Jest test directory: `__tests__` is in the tracker rules'
// `paths.exclude`. Nothing in this file may fire.

const { temHotjar } = require('../deteccao');

test('deteta o loader do Hotjar numa pagina', () => {
  const pagina = '<script src="https://static.hotjar.com/c/hotjar-0000000.js?sv=6"></script>';
  expect(temHotjar(pagina)).toBe(true);
});
