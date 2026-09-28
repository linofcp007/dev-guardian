// A Jest manual mock: `__mocks__` is in the tracker rules' `paths.exclude`.
// The real module loads GA only after consent; the mock returns the markup the
// tests compare against. Nothing in this file may fire.

module.exports = {
  markupDoTag: (id) => `<script async src="https://www.googletagmanager.com/gtag/js?id=${id}"></script>`,
};
