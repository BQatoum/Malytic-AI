# YARA Rules

Place `.yar` or `.yara` rule files here. The static analysis extractor
(`backend/app/services/static_extractors.py`) automatically loads and runs all
rules in this directory against every submitted sample.

An empty directory is valid — the extractor returns an empty match list, not an error.

## Naming convention

Use descriptive filenames that reflect what the rule detects, e.g.:
- `ransomware_generic.yar`
- `mimikatz_strings.yar`
- `cobalt_strike_beacon.yara`

Each file may contain multiple rules. Rule names within a file must be unique
across the whole directory (yara-python uses the filename stem as the namespace).

## Sources

Good starting points for publicly available rules:
- https://github.com/Yara-Rules/rules
- https://github.com/Neo23x0/signature-base
- https://github.com/mandiant/red_team_tool_countermeasures
