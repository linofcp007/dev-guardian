/**
 * `trivy config` judged by what it logged, never by its exit code alone
 * (review I3) — scan_iac's `trivy-config` pass and scan_containers'
 * `trivy-dockerfile` pass.
 *
 * ---- The defect ------------------------------------------------------------
 *
 * Both passes ran `trivy config --quiet` and read exit 0 as `ok`. Trivy drops
 * a file it cannot parse with a single ERROR log line and exits 0 — and
 * `--quiet` suppresses that line too (measured on 0.69.3: stderr empty).
 * Reproduced:
 *   - a .tf with an open security group → 1 high; the same file with an
 *     unclosed `resource "…" "…" {` appended → 0 findings, coverage full;
 *     the log says `ERROR [terraform parser] Error parsing file
 *     file_path="main.tf" err="main.tf:11,30-31: Unclosed configuration
 *     block; …"`;
 *   - a Dockerfile with `HEALTHCHECK --interval=bogus` → `ERROR [dockerfile
 *     scanner] Failed to parse file file_path="Dockerfile" err="…invalid
 *     duration…"`, and trivy-dockerfile ok;
 *   - a Kubernetes Pod made a template (`name: {{ name }}`) → 0, full, and
 *     NO error at all: Trivy logs only `Detected config files num=0`.
 *
 * ---- What this does --------------------------------------------------------
 *
 * The passes run without `--quiet` (the only output that changes is the log
 * on stderr: the report goes to `--output`). A parse error names its file in
 * a partial pass (`ok`, and its name in `missing_tools`, the reason naming
 * the files and Trivy's own error). A file that looks like IaC
 * ({@link iacLookingFiles}) and that the report does not name is partial too
 * — "no config file recognised" when Trivy detected nothing, "Trivy read
 * nothing from N IaC-looking file(s)" otherwise — naming them.
 *
 * ---- What "looks like IaC": what Trivy itself detects (round 2, item 3) ----
 *
 * The rule is Trivy's own detection (`pkg/iac/detection/detect.go`), never
 * a looser guess, so a project Trivy legitimately reads nothing from is not
 * partial forever. Measured with `trivy config` on 0.69.3, each case alone:
 *
 *   - Kubernetes: YAML/JSON with top-level `apiVersion`, `kind` AND
 *     `metadata` in some document. A kustomization.yaml / Kustomize
 *     Component (no `metadata`) was num=0; the same file with `metadata` was
 *     num=1; a skaffold.yaml and a kind cluster config were num=0. The kind
 *     does not matter: a CustomResourceDefinition, a custom resource
 *     (`example.com/v1 Widget`) and a cert-manager Certificate were num=1
 *     each — detection is not limited to core kinds. A base + overlay was
 *     num=2 (the Deployment and the strategic-merge patch).
 *   - Terraform / OpenTofu: `.tf`, `.tf.json`, `.tofu`, `.tofu.json` — not a
 *     `.tfvars` alone (num=0).
 *   - Dockerfiles by Trivy's names, case as it compares them: `Dockerfile` /
 *     `Containerfile`, `Dockerfile.<x>`, `<x>.Dockerfile` / `.Containerfile`.
 *     A lowercase `dockerfile` was num=0.
 *   - CloudFormation (`AWSTemplateFormatVersion`, or `Resources` with an
 *     `AWS::` type) and Azure ARM templates.
 *   - Helm is NOT sniffed: a `Chart.yaml` alone, or a chart that renders no
 *     manifest (a library chart), is num=0 legitimately, and a chart that
 *     fails to render is reported by Trivy's own `ERROR [helm scanner]
 *     Failed to render Chart files` line (measured), which the parse-error
 *     path above names. The `templates/` of a directory holding `Chart.yaml`
 *     is not entered either: a template its values disable
 *     (`{{- if .Values.ingress.enabled }}`) renders nothing and is absent
 *     from the report legitimately (measured: num=1, only the enabled one).
 *
 * ---- Per file, not per run (round 4, item 1) --------------------------------
 *
 * The unrecognised-file check used to run only when Trivy detected NOTHING,
 * so a templated pod.yaml beside one clean Dockerfile read full (num=1).
 * Trivy lists every file it read in `Results` — clean ones too, with their
 * `MisconfSummary` Successes — so each IaC-looking file is compared with the
 * report's Targets ({@link readByTrivy}); any it does not name is partial.
 *
 * What this keeps catching is the I3 case: a manifest Trivy could not parse
 * — `name: {{ name }}` outside a chart, core kind or custom — has all three
 * keys at column 0 and was num=0 with no error.
 */
import { closeSync, openSync, readdirSync, readFileSync, readSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { PROJECT_WALK_EXCLUDE } from './projectFiles.js';
import { asArray, getProp, getString, parseInputAsJson } from './scannerParsers/index.js';
import { withHonoured } from './trivyRun.js';
/** An ANSI colour sequence (ESC [ … letter), in case a log is ever coloured. */
const ANSI = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*[A-Za-z]`, 'g');
/** `key="value with \"escapes\""` or `key=bare` pairs of one log line. */
function logFields(text) {
    const out = new Map();
    for (const m of text.matchAll(/([A-Za-z_]+)=(?:"((?:[^"\\]|\\.)*)"|(\S+))/g)) {
        const key = m[1];
        if (key === undefined)
            continue;
        const quoted = m[2];
        out.set(key, quoted !== undefined ? quoted.replace(/\\(.)/g, '$1') : (m[3] ?? ''));
    }
    return out;
}
/** Trivy's log (stderr, tab-separated: time, level, message, fields). */
export function parseTrivyConfigLog(stderr) {
    let detected = null;
    const parseErrors = [];
    const seen = new Set();
    for (const rawLine of stderr.split(/\r?\n/)) {
        const line = rawLine.replace(ANSI, '');
        const parts = line.split('\t');
        const level = parts[1]?.trim();
        const message = parts[2]?.trim() ?? '';
        const fields = logFields(parts.slice(3).join('\t'));
        if (level === 'INFO' && message === 'Detected config files') {
            const n = Number(fields.get('num'));
            if (Number.isInteger(n) && n >= 0)
                detected = n;
            continue;
        }
        if (level !== 'ERROR')
            continue;
        const what = message.replace(/^\[[^\]]*\]\s*/, '');
        const err = fields.get('err');
        const file = fields.get('file_path') ?? null;
        const key = file ?? `?${what}${err ?? ''}`;
        if (seen.has(key))
            continue;
        seen.add(key);
        parseErrors.push({ file, message: err !== undefined ? `${what}: ${err}` : what });
    }
    return { detected, parseErrors };
}
// ---------------------------------------------------------------- what looks like IaC
/** The ceiling the other project walks use. */
const MAX_WALK_DIRS = 20_000;
/** YAML / JSON files whose head is read to decide, at most. */
const MAX_SNIFFED = 2_000;
/** Bytes read from the head of each. */
const SNIFF_BYTES = 64 * 1024;
/** Trivy's Dockerfile names, compared as it compares them (case-sensitive). */
function isDockerfileName(name) {
    const dot = name.lastIndexOf('.');
    const stem = dot > 0 ? name.slice(0, dot) : name;
    const ext = dot > 0 ? name.slice(dot) : '';
    return stem === 'Dockerfile' || stem === 'Containerfile' || ext === '.Dockerfile' || ext === '.Containerfile';
}
const TERRAFORM = /\.(tf|tf\.json|tofu|tofu\.json)$/;
function head(abs) {
    let fd = null;
    try {
        fd = openSync(abs, 'r');
        const buf = Buffer.alloc(SNIFF_BYTES);
        const n = readSync(fd, buf, 0, SNIFF_BYTES, 0);
        return buf.subarray(0, n).toString('utf8');
    }
    catch {
        return null;
    }
    finally {
        if (fd !== null) {
            try {
                closeSync(fd);
            }
            catch {
                /* closing a read-only descriptor: nothing to lose */
            }
        }
    }
}
/** JSON files larger than this are not parsed to decide (and not counted as IaC-looking). */
const MAX_JSON_BYTES = 2 * 1024 * 1024;
/**
 * A JSON document's TOP-LEVEL keys decide (round 4, item 7): the three
 * Kubernetes keys anywhere used to match a JSON Schema that merely lists them
 * as properties. Parsed, bounded; an array, a non-object or a file that does
 * not parse is not IaC-looking — Trivy's own JSON detection decodes an object.
 */
function looksLikeIacJson(text) {
    let doc;
    try {
        doc = JSON.parse(text.replace(/^\uFEFF/, ''));
    }
    catch {
        return false;
    }
    if (typeof doc !== 'object' || doc === null || Array.isArray(doc))
        return false;
    const top = doc;
    if ('apiVersion' in top && 'kind' in top && 'metadata' in top)
        return true;
    if ('AWSTemplateFormatVersion' in top)
        return true;
    const schema = top['$schema'];
    if (typeof schema === 'string' && /deploymentTemplate\.json/i.test(schema))
        return true;
    const resources = top['Resources'];
    if (typeof resources === 'object' && resources !== null && !Array.isArray(resources)) {
        return Object.values(resources).some((r) => {
            const type = typeof r === 'object' && r !== null ? r['Type'] : undefined;
            return typeof type === 'string' && type.startsWith('AWS::');
        });
    }
    return false;
}
/** The whole file when it is at most `max` bytes; null otherwise, or unreadable. */
function whole(abs, max) {
    try {
        if (statSync(abs).size > max)
            return null;
        return readFileSync(abs, 'utf8');
    }
    catch {
        return null;
    }
}
function looksLikeIacText(text) {
    // YAML: top-level keys only (column 0), so a nested `kind:` never counts;
    // all three of Trivy's keys in one document.
    const documents = text.split(/^---[^\n]*$/m);
    if (documents.some((d) => /^apiVersion:\s*\S/m.test(d) && /^kind:\s*\S/m.test(d) && /^metadata:/m.test(d)))
        return true;
    if (/^AWSTemplateFormatVersion:/m.test(text))
        return true;
    return /^Resources:\s*$/m.test(text) && /^\s+Type:\s*['"]?AWS::/m.test(text);
}
/**
 * Files under `projectPath` that look like something `trivy config` scans —
 * see the module comment for how narrow that is. Bounded like the other
 * project walks: `PROJECT_WALK_EXCLUDE`, hidden directories, a chart's
 * `templates/` and `.guardianignore` entries are not entered, symbolic links
 * not followed; a JSON file is parsed only up to 2 MB.
 */
export function iacLookingFiles(projectPath, exclusions) {
    const files = [];
    const stack = [''];
    let visited = 0;
    let sniffed = 0;
    let incomplete;
    while (stack.length > 0) {
        const rel = stack.pop();
        if (rel === undefined)
            break;
        if (visited >= MAX_WALK_DIRS) {
            incomplete = `the walk stopped after ${MAX_WALK_DIRS} directories`;
            break;
        }
        visited += 1;
        const abs = rel === '' ? projectPath : join(projectPath, ...rel.split('/'));
        let entries;
        try {
            entries = readdirSync(abs, { withFileTypes: true });
        }
        catch {
            continue;
        }
        // A chart's templates are Helm's to render (module comment): one disabled
        // by its values renders nothing and is absent from the report legitimately.
        const isChart = entries.some((e) => e.isFile() && e.name === 'Chart.yaml');
        for (const e of entries) {
            const child = rel === '' ? e.name : `${rel}/${e.name}`;
            if (e.isDirectory()) {
                if (PROJECT_WALK_EXCLUDE.has(e.name) || e.name.startsWith('.'))
                    continue;
                if (isChart && e.name === 'templates')
                    continue;
                if (exclusions !== null && exclusions.ignores(child, true))
                    continue;
                stack.push(child);
                continue;
            }
            if (!e.isFile())
                continue;
            if (exclusions !== null && exclusions.ignores(child, false))
                continue;
            const lower = e.name.toLowerCase();
            if (TERRAFORM.test(e.name) || isDockerfileName(e.name)) {
                files.push(child);
                continue;
            }
            if (!/\.(ya?ml|json|template)$/.test(lower) || lower === 'package.json' || lower.startsWith('docker-compose'))
                continue;
            if (sniffed >= MAX_SNIFFED) {
                incomplete ??= `read the head of ${MAX_SNIFFED} YAML/JSON files at most`;
                continue;
            }
            sniffed += 1;
            if (lower.endsWith('.json')) {
                const text = whole(join(abs, e.name), MAX_JSON_BYTES);
                if (text !== null && looksLikeIacJson(text))
                    files.push(child);
                continue;
            }
            const text = head(join(abs, e.name));
            if (text !== null && looksLikeIacText(text))
                files.push(child);
        }
    }
    files.sort();
    return incomplete !== undefined ? { files, incomplete } : { files };
}
const MAX_NAMED = 5;
const MAX_MESSAGE = 200;
function clip(text) {
    return text.length > MAX_MESSAGE ? `${text.slice(0, MAX_MESSAGE - 1)}…` : text;
}
function named(items) {
    const shown = items.slice(0, MAX_NAMED).join(', ');
    return items.length > MAX_NAMED ? `${shown} and ${items.length - MAX_NAMED} more` : shown;
}
/** Each Result's `Target` (`/`-separated) and `Type`, from the report; empty when there is none. */
function reportTargets(raw) {
    if (raw === null)
        return [];
    try {
        return asArray(getProp(parseInputAsJson(raw), 'Results')).flatMap((r) => {
            const target = getString(r, 'Target');
            return target === undefined ? [] : [{ target: target.split('\\').join('/').replace(/^\.\//, ''), type: getString(r, 'Type') ?? '' }];
        });
    }
    catch {
        return [];
    }
}
const TERRAFORM_FILE = /\.(tf|tf\.json|tofu|tofu\.json)$/;
/**
 * Whether Trivy's report covers `file`. Measured on 0.69.3: a Dockerfile,
 * a manifest or a CloudFormation template is its own Target; Terraform is
 * reported per module DIRECTORY (`infra`, `.` at the root), and a file of it
 * with findings also by name — so a `.tf` counts as read when a terraform
 * Result names its directory or any file in it. A single-file target
 * (scan_containers) is named by its base name.
 */
function readByTrivy(file, read, singleFile) {
    const slash = file.lastIndexOf('/');
    const dir = slash < 0 ? '' : file.slice(0, slash);
    const base = file.slice(slash + 1);
    return read.some(({ target, type }) => {
        if (target === file)
            return true;
        if (singleFile && target === base)
            return true;
        if (TERRAFORM_FILE.test(file) && type.startsWith('terraform')) {
            const t = target === '.' ? '' : target;
            if (t === dir)
                return true;
            const tSlash = t.lastIndexOf('/');
            return (tSlash < 0 ? '' : t.slice(0, tSlash)) === dir && TERRAFORM_FILE.test(t);
        }
        return false;
    });
}
/**
 * The `tools_run` entry of one `trivy config` pass — see the module comment.
 * `iacFiles` are what should have been recognised, relative to the pass's
 * target (for scan_containers: the Dockerfile it was given).
 */
export function judgeTrivyConfig(args) {
    const { name, run, raw, iacFiles } = args;
    if (run.outcome !== 'completed') {
        return { toolRun: withHonoured({ name, status: 'failed', reason: run.outcome }, run), missing: [] };
    }
    const log = parseTrivyConfigLog(run.stderr);
    const gaps = [];
    if (log.parseErrors.length > 0) {
        const items = log.parseErrors.map((e) => (e.file !== null ? `${e.file} (${clip(e.message)})` : clip(e.message)));
        gaps.push(`Trivy could not parse ${log.parseErrors.length} file${log.parseErrors.length === 1 ? '' : 's'}: ${named(items)} — ` +
            'its misconfigurations were not checked');
    }
    // Per file, never only when Trivy detected nothing (round 4, item 1): a
    // templated pod.yaml beside a clean Dockerfile read full on num=1. Trivy
    // lists every file it read in Results — clean ones with their Successes.
    const errored = new Set(log.parseErrors.map((e) => e.file).filter((f) => f !== null));
    const read = reportTargets(raw);
    const unrecognised = iacFiles.filter((f) => !errored.has(f) && !errored.has(f.slice(f.lastIndexOf('/') + 1)) && !readByTrivy(f, read, args.singleFile === true));
    if (unrecognised.length > 0) {
        const detected = log.detected ?? read.length;
        gaps.push(detected === 0
            ? `no config file recognised: Trivy detected 0 config files, but ${named(unrecognised)} look like ` +
                'infrastructure-as-code (a templated manifest or a layout Trivy does not read) — not checked'
            : `Trivy read nothing from ${unrecognised.length} IaC-looking file${unrecognised.length === 1 ? '' : 's'}: ` +
                `${named(unrecognised)} (a templated manifest or a layout Trivy does not read) — not checked`);
    }
    if (gaps.length === 0)
        return { toolRun: withHonoured({ name, status: 'ok' }, run), missing: [] };
    return { toolRun: withHonoured({ name, status: 'ok', reason: gaps.join('; ') }, run), missing: [name] };
}
//# sourceMappingURL=trivyConfig.js.map