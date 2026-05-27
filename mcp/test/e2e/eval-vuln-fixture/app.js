// Intentionally vulnerable file — for dev-guardian E2E only.
// DO NOT USE THIS PATTERN. It is exactly what Semgrep flags.
const http = require('http');
const url = require('url');

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  if (parsed.pathname === '/q') {
    // CWE-95: Improper Neutralization of Directives in Dynamically Evaluated
    // Code. Semgrep's eval-rule should catch this.
    const result = eval(parsed.query.expr);
    res.end(String(result));
    return;
  }
  res.end('hello');
});

server.listen(3000);
