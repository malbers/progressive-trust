"""
PII Inbound Hook — PostToolUse
Scans tool output (Bash, WebFetch) for PII and sensitive tokens before
Claude incorporates it into a response.

⚠⚠ WHAT THIS FILE CAN DO, AND WHAT IT CANNOT — read this before touching the
exit codes. Verified against the Claude Code hook docs on 2026-08-17:

  - PostToolUse exit 2 "shows stderr to Claude; the tool already ran" — informational.
  - `suppressOutput` "has no effect: Claude Code accepts the field but doesn't act on it".
  - PostToolUse has no `updatedOutput` / `permissionDecision`. It is read-only
    observational. ONLY PreToolUse can block or modify (`permissionDecision`,
    `updatedInput`), and by definition it never sees output.

So by the time ANY hook can look at tool output, the value has already been
generated and is bound for the transcript sent to Anthropic. Nothing a
PostToolUse hook does can stop that. This file CANNOT prevent a leak — it can
only detect one, log it, and raise a signal of varying loudness to Claude in
the same turn, in the hope Claude does not restate the value.

Two exit codes, since 2026-08-17 (a deliberate call), and neither one blocks:

  - PII-shaped matches (email, phone, SSN, credit card) → exit 0, with a
    stdout systemMessage. Advisory tier, unchanged from the original design.
  - CREDENTIAL-shaped matches (GitHub token, AWS key, Anthropic key, OpenAI
    key, JWT, private key — see CREDENTIAL_LABELS below) → exit 2, with a
    stderr message. Elevated-signal tier, added 2026-08-17.

  ⚠ Exit 2 is NOT a block. It does not prevent the credential from being
  read, does not remove it from the transcript already sent to Anthropic as
  part of the tool_response payload, and does not stop Claude from acting.
  It is a louder, harder-to-ignore instruction not to echo the value onward
  in the response — a difference in SALIENCE, not enforcement. An earlier
  version of this docstring called this tier "blocking"; that was wrong for
  the reasons above and has been corrected. See the CREDENTIAL_LABELS
  comment block below for why the split is scoped to credentials only.

Why any of this still matters: tool output is part of the Anthropic API
payload. If Claude reads a file or curl response containing credentials or
PII and echoes it back verbatim, that data goes to Anthropic even if you
never typed it.

Allowlist: ~/.claude/.secrets/pii_allowlist.txt (one value per line)
Known-safe values (e.g. your own email addresses) are silently skipped.
Lines beginning with # are treated as comments.

Patterns: same as pii_check.py minus IP addresses (too noisy for tool output —
server IPs appear constantly in bash results and are not sensitive in context).

Per trust-config.md Section 1: bash command credential rule.

★ THE CONSEQUENCE, which is the whole reason this note is long: output-side
credential leaks have no hook-based fix. The only defences that work are
STRUCTURAL — the credential is never in a place a tool might print (git
credential helper instead of a token in a remote URL; secrets read by name via
scripts/authed_call.py instead of inlined) — and MASKING AT THE PRINT SITE inside
whatever holds the secret. Both leaks to date (2026-07-27 STATS_KEY, 2026-08-17
GitHub PAT out of a remote URL) would have been prevented by the structural fix
and by nothing else. See memory/feedback_secret_leak_via_own_scripts.md and
scripts/git_credential_sweep.py.

Roadmap item: todo #149.

Regex patterns for EMAIL, PHONE, SSN, CREDIT_CARD adapted from
DataFog datafog-python (MIT License)
Copyright (c) 2023 Sid Mohan and DataFog Inc.
https://github.com/DataFog/datafog-python
Token patterns are original.
"""
import sys
import json
import re
import os
from datetime import datetime, timezone
from pathlib import Path

# Append-only log of advisories. Shared format with pii_check.py block log.
# Lets Claude detect PII patterns in tool output during stall investigation.
# NEVER write content — only metadata.
_BLOCK_LOG = Path(__file__).parent / ".pii_blocks.log"


def _log_advisory(hits, tool_name, severity="ADVISORY"):
    """One-line marker per advisory/block. Metadata only (label + count, never values)."""
    try:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        summary = ", ".join(f"{label}:{count}" for label, count in hits)
        with open(_BLOCK_LOG, "a", encoding="utf-8") as f:
            f.write(f"{ts} | PostToolUse({tool_name}) | {severity} | {summary}\n")
    except Exception:
        pass

# --- PII Patterns (IP excluded — see module docstring) ---

_EMAIL = re.compile(r"""
    (?<![A-Za-z0-9._%+\-@])
    (?![A-Za-z_]{2,20}=)
    [A-Za-z0-9!#$%&*+\-=^_`{|}~]
    [A-Za-z0-9!#$%&'*+\-=?^_`{|}~.]*
    @
    (?:\.?[A-Za-z0-9-]+\.)+
    [A-Za-z]{2,}
    (?=$|[^A-Za-z])
""", re.VERBOSE)

_PHONE = re.compile(r"""
    (?<![A-Za-z0-9])
    (?:
        (?:(?:\+?1)[-\.\s]?)?
        (?:\(\d{3}\)|\d{3})
        [-\.\s]?
        \d{3}
        [-\.\s]?
        \d{4}
        |
        \+(?!\d{4}-\d{2}-\d{2}(?!\d))\d{1,3}
        [\s\-\.]?
        \d{1,4}
        (?:[\s\-\.]?\d{2,4}){2,3}
    )
    (?![-A-Za-z0-9])
""", re.VERBOSE)

_SSN = re.compile(r"""
    (?<!\d)
    (?:
        (?!000|666)\d{3}-(?!00)\d{2}-(?!0000)\d{4}
        |
        (?!000|666)\d{3}(?!00)\d{2}(?!0000)\d{4}
    )
    (?!\d)
""", re.VERBOSE)

_CREDIT_CARD = re.compile(r"""
    \b
    (?:
        4\d{12}(?:\d{3})?
        |
        5[1-5]\d{14}
        |
        3[47]\d{13}
        |
        (?:
            (?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})
            [-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}
        )
        |
        3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}
    )
    \b
""", re.VERBOSE)

_GITHUB_TOKEN  = re.compile(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}')
_AWS_KEY       = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
_ANTHROPIC_KEY = re.compile(r'sk-ant-[a-zA-Z0-9\-_]{20,}')
_OPENAI_KEY    = re.compile(r'sk-[a-zA-Z0-9\-_]{20,}')
_JWT           = re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]*')
_PRIVATE_KEY   = re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')

PATTERNS = {
    "email":         _EMAIL,
    "phone":         _PHONE,
    "SSN":           _SSN,
    "credit card":   _CREDIT_CARD,
    "GitHub token":  _GITHUB_TOKEN,
    "AWS key":       _AWS_KEY,
    "Anthropic key": _ANTHROPIC_KEY,
    "OpenAI key":    _OPENAI_KEY,
    "JWT":           _JWT,
    "private key":   _PRIVATE_KEY,
}

# --- Elevated-signal tier (A deliberate call:) ---
#
# Credential-shaped matches exit 2 (elevated signal, stderr). PII-shaped matches
# stay advisory (exit 0, stdout). The split is deliberate and is NOT a posture
# compromise, and it is NOT a blocking control — see the module docstring for
# why PostToolUse cannot block. What the split buys is salience:
#
#   - A credential in tool output is always wrong to echo, has no legitimate
#     reason to be restated, and is a bounded, low-false-positive pattern set.
#     It earns the loudest signal this hook can raise.
#   - Email and phone are HIGH-frequency in legitimate output (every Gmail read,
#     every calendar pull, every people-file read). Raising them to the loud
#     tier would fire constantly on correct work, and per
#     the no-posture-downgrade rule the remedy for friction is never
#     "signal less" — but the remedy for a control that cries wolf is to scope
#     it to where it is right, not to widen it until it gets ignored. A loud
#     signal that fires on ordinary work gets ignored, then disabled.
#
# ⚠ SCOPE, stated because it is easy to over-read this change: PostToolUse fires
# AFTER the tool has run. Exit 2 does NOT prevent the credential from being read,
# and does NOT remove it from the transcript already sent to Anthropic. It forces
# a harder-to-skip stderr message instead of a stdout systemMessage, which governs
# whether Claude ECHOES the value onward, not whether the value was read. The
# output-side hole this thread names is not closed by this change and cannot be
# closed by any PostToolUse hook. Closing it requires the value never reaching
# tool output in the first place (structural) or being masked before print.
CREDENTIAL_LABELS = frozenset({
    "GitHub token",
    "AWS key",
    "Anthropic key",
    "OpenAI key",
    "JWT",
    "private key",
})

ALLOWLIST_PATH = os.path.expanduser("~/.claude/.secrets/pii_allowlist.txt")
MAX_SCAN_BYTES = 50_000  # cap at 50KB — keeps hook fast on large outputs


def load_allowlist():
    """Load known-safe values from allowlist file. Returns empty set on any error."""
    try:
        with open(ALLOWLIST_PATH, encoding="utf-8") as f:
            return {
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            }
    except FileNotFoundError:
        return set()
    except Exception:
        return set()


def extract_text(data):
    """Extract scannable text from PostToolUse JSON payload.

    Handles:
      Bash    → tool_response.stdout / tool_response.output
      WebFetch → tool_response.content
      Fallback → str(tool_response)
    """
    response = data.get("tool_response", {})
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        parts = []
        for key in ("stdout", "output", "content", "result", "text", "stderr"):
            val = response.get(key)
            if isinstance(val, str) and val:
                parts.append(val)
        return "\n".join(parts)
    return str(response)


def scan(text, allowlist):
    """Scan text for PII patterns, filtering out allowlisted values.
    Returns list of (label, count) for net hits only.
    """
    found = []
    for label, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        if label == "SSN":
            # Filter false positives from Gmail IDs, timestamps, and other bare 9-digit runs.
            # Real SSNs are XXX-XX-XXXX with dashes; bare 9-digit runs are almost always noise.
            # Mirrors pii_check.py lines 152-155 exactly — posture-neutral for dashed SSNs.
            matches = [m for m in matches if '-' in str(m)]
        net = [str(m).strip() for m in matches if str(m).strip() not in allowlist]
        if net:
            found.append((label, len(net)))
    return found


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)
        data = json.loads(raw)
        text = extract_text(data)
        if not text:
            sys.exit(0)
        text = text[:MAX_SCAN_BYTES]
    except Exception:
        sys.exit(0)  # fail-open — never disrupt workflow on script error

    try:
        allowlist = load_allowlist()
        hits = scan(text, allowlist)
    except Exception:
        sys.exit(0)  # fail-open

    if hits:
        tool_name = data.get("tool_name", "unknown")
        credential_hits = [h for h in hits if h[0] in CREDENTIAL_LABELS]
        pii_hits = [h for h in hits if h[0] not in CREDENTIAL_LABELS]

        if credential_hits:
            _log_advisory(credential_hits, tool_name, severity="ELEVATED")
            if pii_hits:
                _log_advisory(pii_hits, tool_name, severity="ADVISORY")

            lines = [
                "[PII CHECK: CREDENTIAL DETECTED] Credential-shaped data is present in tool output.",
                "This is a signal, not a block — the tool already ran and the output is already",
                "in the transcript. Do not restate the value.",
                "",
                "Matches (label:count, values never shown):",
            ]
            for label, count in credential_hits:
                lines.append(f"  {label}: {count} match(es)")
            if pii_hits:
                lines.append("")
                lines.append("Also present (advisory):")
                for label, count in pii_hits:
                    lines.append(f"  {label}: {count} match(es)")
            lines.append("")
            lines.append(
                "Do not echo, quote, or restate the matched value(s) in your response. "
                "Reference by description only — e.g. 'the token in the output' — never by value."
            )
            lines.append(
                "If a value is known-safe, add it to ~/.claude/.secrets/pii_allowlist.txt to suppress this check."
            )
            print("\n".join(lines), file=sys.stderr)
            sys.exit(2)

        # PII-only path — unchanged advisory behaviour.
        _log_advisory(pii_hits, tool_name, severity="ADVISORY")
        RED   = "\033[31m"
        BOLD  = "\033[1m"
        RESET = "\033[0m"
        lines = [
            f"{BOLD}{RED}🔴 [PII ADVISORY] Sensitive data in tool output — reference by description, not value:{RESET}"
        ]
        for label, count in pii_hits:
            lines.append(f"  {RED}{label}: {count} match(es){RESET}")
        lines.append(
            "Per trust-config.md: say 'the token in the output' not the token itself. "
            "To suppress known-safe values, add them to ~/.claude/.secrets/pii_allowlist.txt"
        )
        print(json.dumps({"systemMessage": "\n".join(lines)}))

    sys.exit(0)


if __name__ == "__main__":
    main()
