// A test-data factory directory: `__factories__` is in the tracker rules'
// `paths.exclude` (measured: a WordPress plugin's datastore tests build their
// pages this way). Nothing in this file may fire.

export function paginaComTag(idMedicao) {
  return `<html><head>
    <script async src="https://www.googletagmanager.com/gtag/js?id=${idMedicao}"></script>
  </head><body></body></html>`;
}
