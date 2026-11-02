# Report template

Use this structure. Keep secrets masked. State the evidence level for every finding.

```markdown
# Supabase security audit: <project name>

- Date: <date>   Auditor: <agent/model>   Skill version: <version>
- Scope: <repo paths, schemas, buckets>   Out of scope: Realtime, Auth settings, Edge Functions, ...
- Verification mode chosen by the user: <A | B | skipped>   Authorization confirmed: <yes/no, date>
- Environment: <local | staging | production>   Host: <host only>

## Summary
<3-5 lines: how many findings by severity, how many VERIFIED, what is still open>

## Findings
| ID | Severity | Title | Evidence | Status |
|---|---|---|---|---|
| F1 | CRITICAL | service_role key in client bundle | scan_secrets SB001 at <file:line>, masked <value> | FIX-PROPOSED |

### F1: <title>
- Where: <file:line or object>
- Evidence: <tool output, probe id, classification>
- Impact: <what an attacker could do>
- Fix: <migration or action>
- Status: DETECTED | REPRODUCED | FIX-PROPOSED | FIX-APPLIED | VERIFIED | NOT-VERIFIED
- Before/after: <probe ids and classifications>

## Before/after probe comparison
<output of compare_probes.py>

## What was not tested
<list, with the reason (mode B, no test user, unverified probe, ...)>

## Actions for the user
<rotations, confirmations, history cleanup, anything you did not do>
```
