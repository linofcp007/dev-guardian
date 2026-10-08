/**
 * Open-set slot names that storage and history both speak: an imported SARIF
 * log's slot is `sarif_import:<source tool>`. Lives here, below both, so the
 * baselines repository need not import `history/`.
 */
const SARIF_PREFIX = 'sarif_import:';
/** The slot of `tool`'s imports. */
export function sarifSlot(tool) {
    return `${SARIF_PREFIX}${tool}`;
}
export function isSarifSlot(slot) {
    return slot.startsWith(SARIF_PREFIX);
}
/** The source tool a slot names. */
export function sarifToolOfSlot(slot) {
    return slot.slice(SARIF_PREFIX.length);
}
/** The slot of a scan's `meta`: a missing or non-string `source_tool` is the empty-name slot. */
export function sarifSlotOfMeta(meta) {
    const tool = meta?.['source_tool'];
    return sarifSlot(typeof tool === 'string' ? tool : '');
}
//# sourceMappingURL=slots.js.map