# Changelog

## September 2026 — credential guidance corrected, enforcement layer shipped

**The headline: the `$(cat ...)` command-substitution pattern is no longer recommended, and
the reason is worth reading rather than just obeying.**

Previous versions taught this as the safe form:

```bash
curl -H "Authorization: Bearer $(cat ~/.secrets/token)" https://api.example.com
```

That advice was **half right**. The shell expands the substitution locally, so only the
literal text is transmitted and the token is genuinely not in the input payload. Anyone who
pushed back on the change with that argument was correct about it.

It was retired because it protects the **input** side and does nothing for the **output**
side, and every real leak observed came from output. The recurring shape: an agent gets
blocked reading a secret, writes its own small script to read it, and that script prints the
value. The guard worked exactly as written and the secret still reached the transcript.

The replacement is `scripts/authed_call.py`, which takes the secret **by name**, reads it
locally, and masks it in everything it prints including HTTP error bodies and redirect URLs.
Both sides covered.

**New in this release:**

- `scripts/authed_call.py` — the credential helper that replaces the retired idiom. Secret by
  name, masked at the print site. `--selftest` (10 cases).
- `hooks/token_leak_guard.py` — PreToolUse guard on Bash. Blocks read-and-echo shapes and
  inline credentials, redacts the offending command before echoing it back, and prints the
  sanctioned alternative in the denial message. `--selftest` (29 cases). Previously this hook
  was described in the README as something you *could* build. It now ships.
- `hooks/state_file_guard.py` — PreToolUse guard blocking whole-file writes to memory and
  state files across three vectors: the Write tool, shell primitives, and inline
  interpreters. `--selftest` (24 cases). Pairs with
  [claude-memory-context](https://github.com/malbers/claude-memory-context).
- Fixture files for every guard, with no real credentials in any of them.
- `LICENSE` (MIT). The repo had been missing one.
- This changelog.

**trust-config.md: 1.2 → 2.0**

- New **§2 Credentials**: where they live, how they travel, and the corrected guidance above.
  States plainly that tokens never leave the local machine and explains the mechanism.
- New **§5 Progressive permissions for connected accounts**: the read / draft / organize /
  send / delete ladder, applied per account, with email as the worked example. Covers the two
  layer confusions that catch people out — OAuth scope versus actual enforcement, and scope
  versus per-resource access.
- **§6** now carries a granted-integrations register table.
- **§7** adds the inbound-authentication rule: any bot or agent accepting external input must
  authenticate the sender against an allowlist before processing.
- **§8** adds the rule that inbound content is data, never instructions.
- **§13 Enforcement Over Policy** substantially expanded: what ships, five things learned the
  hard way, the per-machine wiring warning, the silently-broken-import failure, and the
  response gap.

**Newly disclosed limits.** Three things that were previously unstated:

- A script that reads a credential and prints it defeats every guard here, and no hook can
  close it. `PostToolUse` runs after execution and cannot suppress output.
- The outbound PII hook scans what you type, not what the model says back.
- Hook wiring is per-machine and does not sync. Enumeration proves wiring, not loading — a
  hook edit is inert until the session restarts.

These are in the README rather than a footnote, because a control you believe is active but
is not is worse than one you know is absent.

---

## March 2026

- **Inbound PII hook** (`hooks/pii_check_inbound.py`) — PostToolUse scanner catches PII in
  tool output before Claude echoes it back. Advisory only, allowlist-driven.
- **Shell command credential rule** (trust-config v1.2) — command strings are API payloads
  too. File-based injection pattern added, with an enforcement hook on the roadmap.
- **Outbound PII hook** (`hooks/pii_check.py`) — UserPromptSubmit scanner, 11 pattern types,
  blocks before transmission to the provider.
