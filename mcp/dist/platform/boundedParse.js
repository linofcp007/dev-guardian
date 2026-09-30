/**
 * Parsing a repository's YAML and JSON without letting the file choose how
 * much memory and time the parse takes.
 *
 * A byte cap bounds what is READ, not what a parser builds from it. Measured
 * with `yaml` 2.x on Node 24 (review of 3.0, W2E): the plugin's own 83 KB
 * rule pack parses in ~70 ms and a few MB, but 1 MiB of `- {}` lines took
 * 6 s and 243 MB of heap, 1 MiB of `k: v` lines 5 s and 493 MB, and 8 MiB
 * 1.9–3.7 GB — a 768 MB server dies on one project `.semgrep.yml` under the
 * 16 MiB cap. `JSON.parse` is far cheaper per byte but not free: 60 MiB of
 * `[{},{},…]` under the 64 MiB lock-file cap was 1.35 GB and a 20 s block.
 *
 * What costs is the number of NODES, and that can be counted in one pass
 * without allocating: a YAML node needs a line or a flow indicator, a JSON
 * value a bracket or a comma. A text with more than the caller's bound is
 * refused as `too-complex` — before the parser sees it — and the caller
 * treats that like any file it could not read: named, and never "clean".
 * Real files sit far below the bounds: that 83 KB pack is ~2 600 lines.
 * The JSON half is `platform/boundedJson.ts`, free of any package import.
 */
import { parse as parseYaml } from 'yaml';
import { exceedsCount } from './boundedJson.js';
export { describeTooComplex, JSON_MAX_NODES, parseJsonBounded } from './boundedJson.js';
/** Nodes a configuration or rule file may hold: about a second and under ~100 MB of heap on the worst shapes measured. */
export const YAML_CONFIG_MAX_NODES = 50_000;
/** Nodes an API specification may hold (map_attack_surface imports one per call). */
export const YAML_SPEC_MAX_NODES = 100_000;
/** A YAML node needs a line or a flow indicator: `\n`, `{`, `[`, `,`. */
const YAML_NODE_CHARS = new Set([0x0a, 0x7b, 0x5b, 0x2c]);
/** Whether `text` holds more YAML nodes than `maxNodes` — {@link parseYamlBounded}'s refusal, asked without parsing. */
export function yamlTooComplex(text, maxNodes = YAML_CONFIG_MAX_NODES) {
    return exceedsCount(text, YAML_NODE_CHARS, maxNodes);
}
/** `yaml`'s parse of `text`, when it holds at most `maxNodes` nodes. */
export function parseYamlBounded(text, maxNodes = YAML_CONFIG_MAX_NODES) {
    if (yamlTooComplex(text, maxNodes))
        return { ok: false, reason: 'too-complex' };
    try {
        return { ok: true, value: parseYaml(text) };
    }
    catch (e) {
        return { ok: false, reason: 'invalid', detail: e instanceof Error ? e.message : String(e) };
    }
}
//# sourceMappingURL=boundedParse.js.map