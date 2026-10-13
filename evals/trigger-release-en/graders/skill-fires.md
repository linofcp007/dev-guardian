---
name: 'dev-guardian:guardian-release fires'
type: tool_used
tool: Skill
input_match: '"skill":\s*"dev-guardian:(?:guardian-release)"'
min: 1
---
A go / no-go before a production deploy has one owner: /guardian-release (predeploy) — not security, not review.
