# Consent and preflight checklist

Complete before the first live request to a project. Static work does not need this.

- [ ] The user was asked to choose **A (local/staging)**, **B (project URL)** or **skip**, and answered.
- [ ] The user confirmed they own the project or are authorized to test it.
- [ ] The user confirmed they accept responsibility for the chosen mode.
- [ ] Mode and confirmation are noted for the report (date included).
- [ ] The plan was shown with `--dry-run` and the user saw which requests would be sent.
- [ ] Mode A: the target is local, or the user said it is staging (`--staging-ack`); disposable rows exist or will be seeded.
- [ ] Mode A with writes: the user agreed to `--allow-persisting-writes` and knows how the data will be cleaned.
- [ ] Mode B: the user knows writes will not be verified, and whether they opted in to the partly conclusive write probes.
- [ ] The key in the environment is a publishable key or an anon JWT (the script checks this too).
- [ ] No full key was pasted in chat, files or commands.
- [ ] If any item above is missing or unclear: stop live probing and continue with static analysis only.
