"""
PII Inbound Hook — PostToolUse
Scans tool output (Bash, WebFetch) for PII and sensitive tokens before
the AI incorporates it into a response. Advisory only — never blocks.

Why: Tool output is part of the AI provider's API payload. If the AI reads a
file or curl response containing credentials or PII and echoes it back
verbatim, that data goes to the provider even if you never typed it.

Allowlist: ~/.secrets/pii_allowlist.txt (one value per line)
Known-safe values (e.g. your own email addresses) are silently skipped.
Lines beginning with # are treated as comments.
Adapt ALLOWLIST_PATH below to wherever your secrets live.

Patterns: same as pii_check.py minus IP addresses. IP is excluded because
server IPs appear constantly in bash output and are rarely sensitive in context.
Add it back under PATTERNS if your use case calls for it.

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

# --- PII Patterns (IP excluded — see module docstring) ---

_EMAIL = re.compile(r"""
    (?<![A-Za-z0-9._%+\-@])
    (?![A-Za-z_]{2,20}=)
    [A-Za-z0-9!#$%&*+\-/=^_`{|}~]
    [A-Za-z0-9!#$%&'*+\-/=?^_`{|}~.]*
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
        \+\d{1,3}
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

# Adapt this path to wherever your secrets directory lives.
# Keep the allowlist outside your git repo — it contains real PII values.
ALLOWLIST_PATH = os.path.expanduser("~/.secrets/pii_allowlist.txt")
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
      Bash     → tool_response.stdout / tool_response.output
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
        RED   = "\033[31m"
        BOLD  = "\033[1m"
        RESET = "\033[0m"
        lines = [
            f"{BOLD}{RED}🔴 [PII ADVISORY] Sensitive data in tool output — reference by description, not value:{RESET}"
        ]
        for label, count in hits:
            lines.append(f"  {RED}{label}: {count} match(es){RESET}")
        lines.append(
            "Best practice: say 'the token in the output' not the token itself. "
            "To suppress known-safe values, add them to your allowlist file "
            f"({ALLOWLIST_PATH})."
        )
        print(json.dumps({"systemMessage": "\n".join(lines)}))

    sys.exit(0)


if __name__ == "__main__":
    main()
