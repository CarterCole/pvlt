# Security

pvlt is **pre-alpha and has had no independent security review**. Do not use it for real personal data yet.

Report a vulnerability privately through GitHub's "Report a vulnerability" (Security tab) on this repository. Please
do not open a public issue for one. Include what you found, how to reproduce it, and what it lets an attacker do.
Expect an acknowledgement within a few days; this is a volunteer project and no fixed fix time is promised.

In scope: anything that exposes plaintext or keys, defeats shredding or the shred ledger, bypasses policy,
dual control or the audit log, or breaks the formats in `docs/FORMAT.md`. The threat model is in `REQUIREMENTS.md`.
