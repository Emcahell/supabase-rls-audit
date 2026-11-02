# Sources

Research date: 2026-10-24. Only pages that appeared in the author's web search results are listed.
Most were read as search-result excerpts, not as full pages. Evidence tiers: **official** (vendor
documentation or repository), **secondary** (third-party, used for contrast only).

## What each source supports

| Topic | Source | Tier |
|---|---|---|
| Access depends on grants plus RLS; default privileges changing; Data API can be disabled | https://supabase.com/docs/guides/api/securing-your-api.md and https://supabase.com/docs/guides/database/data-api | official |
| RLS rules: `user_metadata` is user-editable, views and `security_invoker`, `UPDATE` needs `SELECT` | https://supabase.com/docs/guides/auth/row-level-security | official |
| Key types, secret key handling, leaked-key response | https://supabase.com/docs/guides/api/API-keys and https://www.supabase.com/docs/guides/getting-started/api-keys | official |
| Rotation steps for the new key model (create, replace, delete) | https://supabase.com/docs/guides/api/API-keys | official |
| Legacy keys and JWT secret rotation | https://supabase.com/docs/guides/troubleshooting/rotating-anon-service-and-jwt-secrets-1Jq6yd.md | official |
| Key changes announcement (dates differ between sources: see below) | https://supabase.com/changelog/29260-upcoming-changes-to-supabase-api-keys | official |
| splinter lints, including definer functions executable by `anon`/`authenticated` | https://github.com/supabase/splinter | official |
| Official Supabase agent skills (overlap check) | https://github.com/supabase/agent-skills | official |
| RLS-blocked `UPDATE` returns an empty result, not an error | https://github.com/PostgREST/postgrest/discussions/1844 | official (maintainer discussion) |
| Agent Skills format (`name`, `description`, progressive disclosure) | https://agentskills.io/skill.md (the page retrieved; the Phase 2 report cited `/specification`, which was not a retrieved URL) | official |
| Claude Code skills | https://code.claude.com/docs/en/skills | official |
| Codex skills | https://developers.openai.com/codex/skills.md | official |
| OpenCode skills | https://opencode.ai/docs/skills | official |
| Cursor skills | https://cursor.com/docs/skills | official |
| Strict frontmatter validation versus Claude Code extensions | https://github.com/anthropics/claude-code/issues/24826 | official (issue tracker) |
| Secret detection of `service_role` JWTs | https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/supabase_service_role_jwt | secondary |
| Existing tools (overlap and positioning) | https://pypi.org/project/vibe-shipcheck/ , https://glama.ai/mcp/servers/mateuszingano/airlock-rls-mcp , https://skillselion.com/skills/yoanbernabeu/supabase-pentest-skills/supabase-extract-service-key | secondary |

## Compatibility matrix as documented (not as tested)

| Agent | Project skill paths named in its documentation |
|---|---|
| Claude Code | `.claude/skills/` |
| Codex | `.agents/skills` (older material mentions `.codex/skills`: unresolved) |
| OpenCode | `.opencode/skills`, `.claude/skills`, `.agents/skills` |
| Cursor | `.cursor/skills`, `.agents/skills`, `.claude/skills`, `.codex/skills` |

## Known conflicts and open points

- **Legacy key retirement dates** differ between the announcement and later pages. This package states no dates.
- **Default grants for new objects** are described as changing; behavior differs by project age. Check the live project.
- **skills.sh publishing requirements** were only found in third-party pages. Not asserted in the README.
- **Codex `.codex/skills`** appears in older material; the current Codex documentation names `.agents/skills`.
- **Anonymous sign-ins use the `authenticated` role** is the author's recollection, not a retrieved source: verify.
- **PostgREST GET on RPC limited to read-only functions** is the author's recollection: verify.
- **RLS `WITH CHECK` evaluated before other constraints** is the author's recollection of PostgreSQL behavior: unverified.

## Review schedule

Re-read these before each release: key model and rotation pages, `securing-your-api`, splinter lint list,
each agent's skills page (paths and frontmatter), the Agent Skills specification. Re-run all scenarios in
`tests/scenarios.md` whenever a rule changes.
