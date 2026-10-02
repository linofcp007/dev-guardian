/**
 * Briefs — the self-contained text a task is handed out with (US-1.AC-2).
 *
 * A verify brief carries the finding (tool, rule, message, `file:line`), the
 * code around it (the function holding the line, at most 200 lines) between
 * two copies of a random boundary marker, the response schema, and the
 * instruction that everything between the markers is data. Secrets the
 * existing detectors find are replaced by `‹secret: rule, line›` markers
 * before anything reaches the brief (US-1.AC-13). A brief never exceeds
 * {@link MAX_BRIEF_TOKENS} estimated tokens.
 *
 * Templates: `configs/llm-scan/prompts/<version>/{verify,hunt-entrypoint,hunt-crosscut}.md`.
 * Every file is read through the injected contained reader.
 */
/** US-1.AC-2, US-3.AC-3 */
export const MAX_BRIEF_TOKENS = 25_000;
/** US-1.AC-12: the verify brief's P95 over the verification set. */
export const VERIFY_BRIEF_P95_TOKENS = 8_000;
/** The excerpt is the function holding the line, at most this many lines. */
export const MAX_EXCERPT_LINES = 200;
export function estimateTokens(_text) {
    throw new Error('NotImplemented: estimateTokens');
}
export function renderBrief(_task, _ctx) {
    throw new Error('NotImplemented: renderBrief');
}
//# sourceMappingURL=briefs.js.map