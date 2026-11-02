# Final verification checklist

- [ ] No full secret appears in any report, log, file or message (grep the outputs for key prefixes).
- [ ] Every finding has a status (`DETECTED`, `REPRODUCED`, `FIX-PROPOSED`, `FIX-APPLIED`, `VERIFIED`, `NOT-VERIFIED`) and evidence.
- [ ] `VERIFIED` is used only with a before/after probe, a regression probe, and no `INCONCLUSIVE` on the fixed targets.
- [ ] Empty results and missing tables are reported as `INCONCLUSIVE`, never as safe.
- [ ] Grants and RLS were both reviewed for every exposed table.
- [ ] Fixes are new migrations; nothing applied remotely without a yes from the user.
- [ ] Exposed privileged keys: rotation is listed first among the user's actions.
- [ ] The report lists what was not tested and why (mode B, no test user, optional probes skipped, unverified probes).
- [ ] The report names the mode chosen by the user and the date.
- [ ] No Git commit, push, tag or history rewrite was performed.
