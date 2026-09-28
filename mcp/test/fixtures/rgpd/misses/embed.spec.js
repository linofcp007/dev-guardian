// A unit spec (`*.spec.js`, in the tracker rules' `paths.exclude`): the
// embed is input to the function under test. Nothing here may fire.

const { paraNoCookie } = require('./embed');

describe('paraNoCookie', () => {
  it('troca o dominio do embed', () => {
    const entrada = '<iframe src="https://www.youtube.com/embed/abc123"></iframe>';
    expect(paraNoCookie(entrada)).toContain('youtube-nocookie.com');
  });
});
