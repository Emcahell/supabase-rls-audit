# supabase-rls-secrets-audit

An agent skill that audits a Supabase project's **Row Level Security, grants, policies, functions,
views, Storage and exposed secrets**, proposes fixes, and then **proves each fix by testing as the
anonymous role**, before and after. Advice is not the deliverable; evidence is.

> **Status: version 0.1.0, built and tested locally, not published.** The scripts have automated tests
> against a local *simulation* of PostgREST. No real Supabase project and no agent (Claude Code, Codex,
> OpenCode, Cursor) has been used to test it yet. See [Verification status](#verification-status).

## The problem

Supabase projects commonly leak data in repeatable ways: tables without RLS, `USING (true)` policies,
policies that trust `user_metadata`, views that bypass RLS, exposed `SECURITY DEFINER` functions, public
buckets, and a `service_role` or secret key in a client bundle, a committed `.env` file or the Git history.
Reading policies is not enough, and an HTTP `200` is not proof: a blocked read and an empty table both return
`200 []`. This skill audits, fixes and verifies, and it says `INCONCLUSIVE` when the evidence does not settle it.

## When to use it

- Reviewing a Supabase project's security before launch, or after an incident.
- Writing or fixing RLS policies and wanting proof the fix works without breaking signed-in users.
- Checking whether a `service_role`/secret key or database password is exposed.
- Asking "can an anonymous user read or write my data?"

Not for: general application pentesting, Auth provider or MFA configuration, business-logic review, or
projects you do not own or are not authorized to test.

## How it keeps you in control

Before the first **live** request to a project, the agent asks you to choose a verification mode and to
confirm that you own the project and accept responsibility:

| Mode | For | What is allowed |
|---|---|---|
| **A: local or staging** | Safest; recommended when available | Reads, plus write probes that change data, only with an explicit flag and disposable rows |
| **B: project URL, incl. production** | When no safe environment exists | Reads, read-only RPC (GET) and Storage listing. Write protection stays "not verified" unless you opt in to a small set of non-persisting probes whose results are only partly conclusive |
| **Skip** | No live testing | Static analysis and secret scanning only |

Other hard limits: probes use only a publishable or anon key (the script refuses `service_role` and secret
keys), no secret is ever printed (reports carry masked values), nothing remote is changed without your explicit
yes, and the skill does not touch Git history or publish anything.

## What is in the package

```text
supabase-rls-secrets-audit/
├── SKILL.md                      # entry point: consent gate, workflow, rules
├── README.md  LICENSE  SOURCES.md  CHANGELOG.md
├── references/
│   ├── probe-methodology.md      # modes, probe config, classification, unverified points
│   ├── rls-rules.md              # policy, grant, view, function and Storage rules
│   ├── secrets-and-keys.md       # key types, detection, severity, rotation
│   ├── remediation-playbook.md   # writing fix migrations safely
│   └── report-template.md
├── checklists/
│   ├── consent-and-preflight.md
│   └── final-verification.md
├── examples/
│   ├── vulnerable-schema.sql     # intentionally vulnerable fixture
│   ├── fixed-migration.sql       # its fix, as a new migration
│   ├── probe-config.example.json
│   └── sample-report.md          # illustrative, invented values
├── scripts/                      # Python 3, standard library only
│   ├── scan_secrets.py           # working tree (and optional Git history) secret scan, masked output
│   ├── static_rls_audit.py       # heuristic audit of SQL migrations
│   ├── anon_probe.py             # anon / test-user Data API probe with consent gate
│   ├── compare_probes.py         # before/after verdicts and the VERIFIED rule
│   ├── catalog_audit.sql         # read-only catalog queries (not yet executed, see below)
│   └── _common.py                # masking and key classification
└── tests/
    ├── scenarios.md              # 17 behavioral scenarios for an agent (not yet run)
    ├── test_skill_structure.py   # structure, frontmatter, links, self-scan for secrets
    ├── test_scan_secrets.py  test_static_rls_audit.py
    ├── test_probe_classify.py  test_compare_probes.py
    └── _helpers.py
```

## Installation

### Agent Skills (Preferred)

```bash
npx skills add emcahell/frontend-anti-tech-debt-skill
```

This installs to `.agents/skills/frontend-anti-tech-debt/SKILL.md`.

Alternatively, copy the folder manually. A skill is a folder with `SKILL.md`. Copy the folder (named `supabase-rls-secrets-audit`) into the skills location of your agent. The paths below come from each agent's documentation (see `SOURCES.md`). **The copy commands have not been run against the agents.**

| Agent | Project-level folder (documented) | Tested here |
|---|---|---|
| Claude Code | `.claude/skills/` | No |
| Codex | `.agents/skills/` | No |
| OpenCode | `.opencode/skills/`, `.claude/skills/` or `.agents/skills/` | No |
| Cursor | `.cursor/skills/`, `.agents/skills/` or `.claude/skills/` | No |

No single folder is read by all four agents according to their documentation, so the portable approach is
to install into `.agents/skills/` and also into `.claude/skills/`:

```bash
# from your project root; adjust the source path
mkdir -p .agents/skills .claude/skills
cp -R /path/to/supabase-rls-secrets-audit .agents/skills/
cp -R /path/to/supabase-rls-secrets-audit .claude/skills/
```

If you prefer a symlink to avoid two copies, check that your agent and OS follow symlinks (not verified here).
Requirements: Python 3 (tested on 3.12.3). Optional: `psql` for `scripts/catalog_audit.sql`, the Supabase CLI
for a local stack.

**After you publish** the repository yourself, installers such as `npx skills add <OWNER>/<REPO>` may work.
`<OWNER>/<REPO>` is a placeholder; that flow has not been verified for this package.

## Usage

Ask your agent in plain language. Examples:

- "Audit the security of my Supabase project's migrations and check for leaked keys."
- "Fix the RLS on `notes` and prove anonymous users can no longer read or write it. Use my local stack."
- "I think my service_role key leaked. What do I do?"

The agent will ask you for the verification mode before any live request. You can also run the tools directly
(commands below were exercised by the automated tests):

```bash
python3 scripts/static_rls_audit.py supabase/migrations
python3 scripts/scan_secrets.py . --format text
python3 scripts/anon_probe.py --config probe.json --dry-run        # sends nothing
# after you choose a mode and confirm authorization, with the key in an environment variable:
python3 scripts/anon_probe.py --config probe.json --mode A --confirm-authorized --out before.json
python3 scripts/compare_probes.py before.json after.json
```

Put the publishable/anon key in `SUPABASE_ANON_KEY` (or `SUPABASE_PUBLISHABLE_KEY`) and the URL in `SUPABASE_URL`.
Do not paste keys into chat.

## Verification status

| Item | Status |
|---|---|
| `scan_secrets.py`, `static_rls_audit.py`, `compare_probes.py` unit tests | Run locally (see "Run the checks") |
| `anon_probe.py` logic, consent gate, key restrictions | Run locally against a **simulated** PostgREST, not a real project |
| `catalog_audit.sql` | **Not executed** (no PostgreSQL in the build environment) |
| Mode A persisting writes, Storage listing, GET-on-RPC, invalid-insert ordering | **Unverified** against real Supabase (`references/probe-methodology.md`, section 7) |
| Official `skills-ref validate` | **Not run** (not available offline); `tests/test_skill_structure.py` is a local substitute |
| Claude Code, Codex, OpenCode, Cursor | **Not tested**; scenarios in `tests/scenarios.md` are ready for you to run |

## Run the checks

```bash
python3 -m unittest discover -s tests -v
```

`tests/test_skill_structure.py` (structure, frontmatter, links and a self-scan for secrets) is included in that run.

## Limitations

- The static audit is heuristic and reads only the SQL files you give it.
- Mode B cannot confirm that writes are blocked by RLS.
- Not covered: Realtime, Edge Functions, GraphQL, Auth settings, Storage write protection, database extensions.
- A probe cannot distinguish an empty table from RLS filtering without a known row: such results stay `INCONCLUSIVE`.
- Key-model details (legacy versus publishable/secret keys) change over time; the skill checks the live project rather than stating dates.

## Maintenance

Versioning follows SemVer; changes go in `CHANGELOG.md`. Before each release re-read the sources listed in
`SOURCES.md`, re-run the unit tests, and re-run the scenarios in `tests/scenarios.md` for any rule you changed.
Update a rule only after confirming the underlying Supabase behavior in the current documentation.

## Before you publish it yourself (informational checklist)

The author of this package did not publish anything and did not touch Git. When you decide to publish:

1. Put your name or organization in the `LICENSE` copyright line (it currently names "contributors").
2. Run `python3 -m unittest discover -s tests -v`.
3. Run the scenarios in `tests/scenarios.md` in at least one agent and record the results.
4. Run `python3 scripts/scan_secrets.py . --fail-on medium` and confirm no credentials are present.
5. Create the repository, review `git status` and `git diff`, commit and push in your own account.
6. Replace the `<OWNER>/<REPO>` placeholder above and test the installation from the published repository.
7. Check the current publishing requirements of skills.sh and any marketplace before submitting; they were not verified.

## License

MIT. See `LICENSE`.
