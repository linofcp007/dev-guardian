---
name: 'the security scan stays silent'
type: tool_used
tool: Skill
input_match: '"skill":\s*"dev-guardian:(?:guardian-security|guardian-scan)"'
min: 0
max: 0
---
"This smells bad" is a code smell (guardian-quality may fire); the security scan must not.
