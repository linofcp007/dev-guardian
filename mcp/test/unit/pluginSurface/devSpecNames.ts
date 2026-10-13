/**
 * The dev-spec-driven names dev-guardian's prose may cite.
 *
 * dev-guardian hands work to its sibling plugin dev-spec-driven: the
 * `guardian-improve` skill adds improvement seeds to its backlog, and its
 * `/spec-finish` can run dev-guardian's gate as a project check. In Claude
 * Code a model can call only the tools `tools/list` returns. dev-spec-driven
 * 1.26 folded `spec_backlog` into `spec_roadmap_edit { kind: "backlog" }` and
 * kept the old name only as a hidden alias (callable, never listed), so the
 * skill that kept citing `spec_backlog` sent the model to a tool it could
 * not call. `devSpecNames.test.ts` holds every name the prose cites to these
 * lists.
 *
 * Where they come from — dev-spec-driven 1.29.1 (DEV_SPEC_FIXTURE_VERSION; the lists are unchanged since 1.28.0):
 *
 *   - DEV_SPEC_TOOLS: the `TOOLS` array of its `mcp/server.js`, as
 *     `tools/list` returns it in Claude Code plugin mode
 *     (`SPEC_MCP_APPROVAL_HOOK=on`) — 30 of its 32 tools. `PLUGIN_UNLISTED`
 *     leaves out `spec_stop_check` and `spec_log`, whose job the plugin's
 *     hooks do, so no dev-guardian prose may send a model to them.
 *   - DEV_SPEC_COMMANDS: its `commands/*.md` — the 22 commands its 1.26
 *     release folded 55 into.
 *   - DEV_SPEC_HIDDEN_ALIASES and DEV_SPEC_RETIRED_COMMANDS: what that fold
 *     retired, from its server's `LEGACY_TOOLS` and its CHANGELOG's
 *     "Upgrading from 1.25 or earlier", each with what replaced it — only so
 *     a failure can say what to write instead.
 *
 * dev-spec-driven keeps the mirror test on its side — "tools other plugins
 * call stay listed" — so a rename there fails before it reaches this list.
 * When a newer dev-spec-driven adds a name dev-guardian should cite, add it
 * here and bump DEV_SPEC_FIXTURE_VERSION; the live cross-check in the test
 * then holds the list to that version or newer.
 */

export const DEV_SPEC_FIXTURE_VERSION = '1.29.1';

export const DEV_SPEC_TOOLS: readonly string[] = [
  'spec_init',
  'spec_classify',
  'spec_create',
  'spec_status',
  'spec_next_task',
  'spec_task_brief',
  'spec_finish',
  'spec_complete_task',
  'ears_validate',
  'trace_check',
  'spec_doctor',
  'spec_approve',
  'steering_scaffold',
  'spec_roadmap',
  'spec_roadmap_edit',
  'spec_scan',
  'spec_clarify',
  'spec_next_action',
  'spec_add_track',
  'spec_feature',
  'spec_import',
  'spec_append_tasks',
  'spec_impact',
  'spec_metrics',
  'spec_drift',
  'spec_upgrade',
  'spec_templates',
  'spec_tracks',
  'spec_export',
  'spec_decide',
];

/** Without the leading `/`. Only `/spec` and `/spec-bugfix` are model-invocable; the rest are the user's to type. */
export const DEV_SPEC_COMMANDS: readonly string[] = [
  'spec',
  'spec-bugfix',
  'ds',
  'dss',
  'dsx',
  'spec-upgrade',
  'clarify',
  'approve',
  'spec-doctor',
  'executeTask',
  'spec-status',
  'roadmap',
  'spec-review',
  'spec-finish',
  'spec-spike',
  'spec-change',
  'feature',
  'spec-report',
  'spec-adopt',
  'spec-setup',
  'eval',
  'spec-tour',
];

/** Callable, never listed: a Claude Code model cannot reach them. Each with what to cite instead. */
export const DEV_SPEC_HIDDEN_ALIASES: Readonly<Record<string, string>> = {
  spec_list: 'spec_status (no name)',
  spec_backlog: 'spec_roadmap_edit { kind: "backlog" }',
  spec_depend: 'spec_roadmap_edit { kind: "depend" }',
  spec_milestone: 'spec_roadmap_edit { kind: "milestone" }',
  spec_catalog: 'spec_export { format: "catalog" }',
  spec_changelog: 'spec_export { format: "changelog" }',
  spec_coverage: 'spec_scan { coverage: true }',
};

/**
 * The retired commands whose names do not start with `/spec` (every `/spec…`
 * name outside DEV_SPEC_COMMANDS fails anyway), without the leading `/`.
 * `/design`, `/scan`, `/coverage` and `/reverse` were retired too, but they
 * are words a path or a sentence uses (`tools_run`/coverage), so they are
 * not matched.
 */
export const DEV_SPEC_RETIRED_COMMANDS: Readonly<Record<string, string>> = {
  'next-action': '/spec <feature>',
  classify: '/spec <idea>',
  createSpec: '/spec <feature> requirements',
  testPlan: '/spec <feature> test-plan',
  evalPlan: '/spec <feature> eval-plan',
  writeTests: '/spec <feature> tests',
  createTask: '/spec <feature> tasks',
  grill: '/clarify --grill',
  depend: '/roadmap depend',
  backlog: '/roadmap backlog',
  prReview: '/spec-review branch',
  promptReview: '/spec-review prompt',
  'add-track': '/spec-change track',
  migrateModel: '/eval migrate',
};
