# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versioning: [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-24
Initial local build (not published, not tagged).

### Added
- `SKILL.md` with the consent gate (mode A local/staging, mode B project URL, or skip), workflow, rules and reference map.
- `scripts/scan_secrets.py`, `scripts/static_rls_audit.py`, `scripts/anon_probe.py`, `scripts/compare_probes.py`, `scripts/catalog_audit.sql`.
- References, checklists, examples, scenario definitions and automated tests.

### Known limitations
- Probes were tested against a local simulation of PostgREST responses, not a real Supabase project.
- `scripts/catalog_audit.sql` has not been executed.
- No agent (Claude Code, Codex, OpenCode, Cursor) has run the skill yet.
