# Secrets and keys

## Contents
1. Key types
2. Detection
3. Severity
4. Rotation
5. Public-prefix variables
6. Git history
7. Verify the current key model

## 1. Key types

| Key | Public? | Notes |
|---|---|---|
| Publishable key (`sb_publishable_...`) | Yes, by design | Safe only because RLS and grants protect the data |
| Legacy `anon` JWT | Yes, by design | Same role as publishable |
| Secret key (`sb_secret_...`) | **No** | Bypasses RLS. Backend only; the platform advises one per backend component |
| Legacy `service_role` JWT | **No** | Bypasses RLS. Tied to the project's JWT secret in the legacy model |
| Database password / connection string | **No** | Direct access to Postgres |
| JWT secret (legacy) | **No** | Anyone with it can mint valid JWTs |
| A user's access token | No | A session credential; revoke the session |

Do not classify a JWT as secret just because it is a JWT: decode the payload and read `role`
(`scripts/_common.py` does this without verifying the signature, for classification only).

## 2. Detection

`scripts/scan_secrets.py` reports (masked): `service_role` JWTs, `sb_secret_` keys, session JWTs,
database URLs with real passwords, secret-named variables with a public prefix, env files that are
not ignored or are tracked, and `'use client'` files that mention `SERVICE_ROLE`. Also look at:
- built output (`.next`, `dist`, `build`): a key there is publicly exposed once deployed
- CI config, Dockerfiles, mobile app configs, `README` snippets, test fixtures
- values pasted in tickets or chats (ask the user; the scanner cannot see them)

## 3. Severity

| Finding | Severity |
|---|---|
| `service_role` JWT or `sb_secret_` key in code, bundle, history or a tracked env file | CRITICAL |
| Database URL with password to a hosted project | HIGH |
| Secret-named variable with a public prefix | HIGH |
| Tracked env file | HIGH |
| Env file not covered by `.gitignore` | MEDIUM |
| User session token committed | MEDIUM |
| `anon` / publishable key | INFO (its safety depends on RLS, not on secrecy) |

## 4. Rotation (ask before doing anything remote)

1. Assume the key is compromised from the moment it was exposed. Rotate **first**; cleaning code does not
   un-leak it.
2. With the current key model: create a new secret key, update every backend that uses it, then delete the
   compromised key. Deleting is irreversible, so confirm the new key works first.
3. With legacy keys, changing the JWT secret invalidates existing sessions and keys; the platform
   recommends migrating to the new model. Follow the current official guide for the project.
4. Rotate a leaked database password and update the connection strings.
5. Review logs and data for misuse around the exposure window, and tell the user what you could not check.
6. Then remove the key from code and config, and use environment variables on the server.

The user performs the rotation in the Dashboard unless they explicitly ask you to do it and have given you
the means. Never ask for the key itself.

## 5. Public-prefix variables

Frameworks inline variables with prefixes like `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_` into
the client bundle. A secret behind such a prefix is public. Server-only code (route handlers, server
actions, Edge Functions) reads unprefixed variables.

## 6. Git history

A removed secret stays in history. Offer a read-only history scan (`--history`). Cleaning history (for
example with `git filter-repo` or BFG) and force-pushing are the user's decision and action; rotation
makes the old value harmless regardless.

## 7. Verify the current key model

The key model has been changing (legacy to publishable/secret keys), and sources disagree on dates.
Do not state dates or versions. Check the project's API-keys settings and the current Supabase
documentation, and say which model the project uses.
