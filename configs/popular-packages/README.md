# Popular-packages lists

Data for the typosquat check in package vetting (`vet_packages` and the
PreToolUse install-command hook). A package name that is a near-miss of a name
in these lists gets a **warning**; a name that is in a list is never flagged.
The lists never block anything.

| file | registry | names |
| --- | --- | --- |
| `npm.txt` | npmjs.org | 2000 |
| `pypi.txt` | pypi.org | 2000 |
| `packagist.txt` | packagist.org | 2000 |
| `nuget.txt` | nuget.org | 2000 |

## Where they come from

Generated, never typed by hand — a name typed from memory is exactly the kind
of near-miss the check exists to catch.

- **Source:** [ecosyste.ms](https://packages.ecosyste.ms), an open index of
  every one of these registries, through its names-only endpoint sorted by
  download count:
  `https://packages.ecosyste.ms/api/v1/registries/<registry>/package_names?sort=downloads&order=desc`.
  One source for all four, so each list means the same thing: the N
  most-downloaded names.
- **Generated:** 2026-09-25, 2000 names per ecosystem.
- **Regenerate:** `node mcp/scripts/generatePopularPackages.mjs` (all four) or
  `node mcp/scripts/generatePopularPackages.mjs npm pypi` (a subset). Each file
  records its own source URL, date and count in a `#` header.

After regenerating, run `npm test` in `mcp/`:
`test/unit/pkgvet/popularLists.test.ts` re-measures the table below and fails
until the numbers here and in the test are updated to match.

## Self-collision measurement

Every entry of a list, checked against the **rest of the same list** with the
popular-name exemption switched off. Each hit is a pair of real, legitimate
packages the check would confuse if one of them were not in the list — the
best available proxy for its false-positive rate on real packages.

| ecosystem | names | flagged | share | pairs |
| --- | --- | --- | --- | --- |
| npm | 2000 | 49 | 2.5% | 25 |
| pypi | 2000 | 90 | 4.5% | 47 |
| packagist | 2000 | 2 | 0.1% | 1 |
| nuget | 2000 | 42 | 2.1% | 22 |

(`flagged` counts both sides of a pair, plus the odd entry whose nearest
neighbour is a third name.)

### What brought it down

Measured on the same lists at the same size, before and after each rule in
`mcp/src/pkgvet/typosquat.ts`:

| rules in force | npm | pypi | packagist | nuget |
| --- | --- | --- | --- | --- |
| length thresholds + normalization | 101 | 113 | 78 | 198 |
| + owner namespaces not compared | 73 | 113 | 2 | 198 |
| + sibling families (the last three bullets) | 49 | 90 | 2 | 42 |

- **Length thresholds** (distance ≤ 2 from 8 characters, ≤ 1 for 5-7, nothing
  under 5) and **normalized comparison** (PEP 503 for PyPI, lower case
  elsewhere) apply throughout.
- **Owner namespaces are not compared.** An npm scope and a Packagist vendor
  can only be published into by their owner, so `@aws-sdk/client-sts` next to
  `@aws-sdk/client-s3` is never a squat. That alone took Packagist from 78
  to 2 — every one of the 76 it removed was two packages of the same vendor.
- **Only the numbers changed** — `…-cu12` / `…-cu13`,
  `…manifest-8.0.100` / `…manifest-9.0.100`, `net472` / `net48`. This took
  NuGet from 198 to 42. An *inserted* number is still flagged:
  `python3-dateutil` was a real PyPI typosquat.
- **One short code swapped** (both sides at most 2 characters): locale and
  architecture suffixes such as `humanizer.core.uk` / `.sk`.
- **One word swapped at distance 2** (the differing segment changed by at
  least 40%): `is-stream` / `zip-stream`, `pytest-cov` / `pytest-env`,
  `mypy-boto3-s3` / `mypy-boto3-sqs`. A one-edit change is never excused this
  way.

Larger lists collide more (npm 3.3%, PyPI 6.6% at 5000 names), which is why
2000 was chosen: it covers the names typosquatters actually target while
keeping the collisions to the pairs below.

### What remains, and why it is acceptable

Every remaining pair is two real packages whose names genuinely are one slip
apart — the confusable shapes a squatter would reach for:

- **npm (25 pairs):** `safe-buffer` / `safer-buffer`, `camelcase` /
  `camel-case`, `word-wrap` / `wordwrap`, `object-assign` / `object.assign`,
  `http-proxy-agent` / `https-proxy-agent`, `react` / `preact`,
  `inquirer` / `enquirer`, `through` / `through2`, `extend` / `xtend`,
  `color` / `colors`, …
- **PyPI (47 pairs):** a flat namespace full of short look-alikes — `pyyaml` /
  `pyaml`, `attrs` / `cattrs`, `chardet` / `cchardet`, `oauthlib` / `authlib`,
  `pymysql` / `pymssql`, `ujson` / `ijson` / `hjson`, `psycopg` / `psycopg2`,
  `pypdf` / `pypdf2` — and version-suffixed forks (`httpx` / `httpx2`,
  `markdown` / `markdown2`), which are the digit-*insertion* shape the check
  keeps on purpose.
- **Packagist (1 pair):** `php-di/php-di` / `php-ds/php-ds`.
- **NuGet (22 pairs):** `nunit` / `xunit`, `mvc.core` / `mvc.cors`,
  `awssdk.ec2` / `.ecr` / `.ecs`, `hosting` / `routing`, and the `win` /
  `win7` runtime identifiers.

Any of these would be a correct warning if the second name were not itself
popular. They are the check doing its job on names that happen to be real; the
exemption for listed names is what keeps them silent in practice.
