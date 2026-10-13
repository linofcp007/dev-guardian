---
type: regex
target: trace
pattern: '"skill":\s*"dev-spec-driven:[\w-]+"|"name":"mcp__plugin_dev-spec-driven_spec-driven__spec_(?:next_action|create|status)"'
---
The reported bug reaches dev-spec-driven: its skill or `/spec-bugfix` fires, or its tools are asked where the
feature stands (`spec_next_action`, `spec_status`) or to open the bugfix (`spec_create { kind: "bugfix" }`).
