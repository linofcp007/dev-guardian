// A unit test: the tracker markup here is INPUT to the code under test and is
// never served to a visitor. `*.test.*` is in the tracker rules'
// `paths.exclude` (measured on application code: Site Kit and Ghost carry
// exactly this shape). Nothing in this file may fire.

const { extrairIdDoTag } = require('./tags');

describe('extrairIdDoTag', () => {
  it('le o id do loader do gtag', () => {
    const html = `<script async src="https://www.googletagmanager.com/gtag/js?id=G-TESTE123"></script>`;
    expect(extrairIdDoTag(html)).toBe('G-TESTE123');
  });
});
