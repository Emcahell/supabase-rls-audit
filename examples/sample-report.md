> **ILLUSTRATIVE EXAMPLE. Every name, value and result below is invented to show the format.
> It is not evidence of any real test.**

# Supabase security audit: example-project

- Date: 2026-01-01   Skill version: 0.1.0
- Scope: `supabase/migrations`, public schema, bucket `avatars`
- Verification mode chosen by the user: A (local). Authorization confirmed: yes
- Environment: local   Host: 127.0.0.1

## Summary
4 findings: 1 CRITICAL, 2 HIGH, 1 MEDIUM. 3 VERIFIED, 1 open (key rotation is the user's action).

| ID | Severity | Title | Evidence | Status |
|---|---|---|---|---|
| F1 | CRITICAL | Secret key in client bundle | scan_secrets SB002, `sb_secret_…(len=…)` in `dist/app.js` | FIX-PROPOSED |
| F2 | HIGH | `profiles` has no RLS and anon has write grants | static `RLS_NOT_ENABLED`; probe `read:profiles` LEAK | VERIFIED |
| F3 | HIGH | `notes` policy `USING (true)` | static `POLICY_TRUE_WRITE`; probe `insert:notes` LEAK | VERIFIED |
| F4 | MEDIUM | View `invoice_totals` ignores RLS | static `VIEW_NO_SECURITY_INVOKER`; probe `read:invoice_totals` LEAK | VERIFIED |

## Before/after probe comparison
| Probe | Before | After | Verdict |
|---|---|---|---|
| read:profiles | LEAK | BLOCKED-GRANT | FIXED |
| insert:notes | LEAK | BLOCKED-RLS | FIXED |
| read:invoice_totals | LEAK | BLOCKED-RLS | FIXED |
| read:notes (authenticated, expect ALLOW) | ALLOWED | ALLOWED | STILL-ALLOWED |

## What was not tested
Realtime, Auth settings, Edge Functions. Storage write protection (listing only).

## Actions for the user
1. Rotate the exposed secret key, then remove it from the bundle and rebuild.
2. Review the Git history for the same key (read-only scan offered, not run).
