#!/usr/bin/env python3
"""
PII Warning Hook — UserPromptSubmit
Scans outgoing Claude Code messages for PII and sensitive tokens.
Warns before content is transmitted to Anthropic. Does not block — warns only.
Per trust-config.md: Claude Code sessions transmit to Anthropic; don't type third-party PII directly.

Regex patterns for EMAIL, PHONE, SSN, CREDIT_CARD, IP_ADDRESS
adapted from DataFog datafog-python (MIT License)
Copyright (c) 2023 Sid Mohan and DataFog Inc.
https://github.com/DataFog/datafog-python
"""
import sys
import json
import re

# --- PII Patterns (adapted from DataFog datafog-python, MIT License) ---

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
        4\d{12}(?:\d{3})?                           # Visa
        |
        5[1-5]\d{14}                                # Mastercard
        |
        3[47]\d{13}                                 # Amex (15 digits)
        |
        (?:
            (?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})
            [-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}
        )                                           # Visa/MC/Amex with separators
        |
        3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}           # Amex alternate with separators
    )
    \b
""", re.VERBOSE)

_IP_ADDRESS = re.compile(r"""
    \b
    (?:
        (?:25[0-5]|2[0-4]\d|1?\d?\d)\.
        (?:25[0-5]|2[0-4]\d|1?\d?\d)\.
        (?:25[0-5]|2[0-4]\d|1?\d?\d)\.
        (?:25[0-5]|2[0-4]\d|1?\d?\d)
    )
    \b
""", re.VERBOSE)

# --- Token / Secret Patterns ---

_GITHUB_TOKEN   = re.compile(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}')
_AWS_KEY        = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
_ANTHROPIC_KEY  = re.compile(r'sk-ant-[a-zA-Z0-9\-_]{20,}')
_OPENAI_KEY     = re.compile(r'sk-[a-zA-Z0-9\-_]{20,}')
_JWT            = re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]*')
_PRIVATE_KEY    = re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')

PATTERNS = {
    "email":        _EMAIL,
    "phone":        _PHONE,
    "SSN":          _SSN,
    "credit card":  _CREDIT_CARD,
    "IP address":   _IP_ADDRESS,
    "GitHub token": _GITHUB_TOKEN,
    "AWS key":      _AWS_KEY,
    "Anthropic key":_ANTHROPIC_KEY,
    "OpenAI key":   _OPENAI_KEY,
    "JWT":          _JWT,
    "private key":  _PRIVATE_KEY,
}


def scan(text):
    found = []
    for label, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            found.append((label, matches))
    return found


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)
        data = json.loads(raw)
        text = data.get("prompt", "") or data.get("message", "") or str(data)
    except Exception:
        sys.exit(0)  # always fail-open — never block on script error

    hits = scan(text)
    if hits:
        lines = ["[PII WARNING] Sensitive data detected before sending to Anthropic:"]
        for label, matches in hits:
            lines.append(f"  {label}: {', '.join(str(m) for m in matches[:3])}")
        lines.append("Consider referencing a local file instead. See trust-config.md.")
        sys.stderr.buffer.write(("\n".join(lines) + "\n").encode("utf-8"))
        sys.exit(2)  # exit 2 = block with message shown to user

    sys.exit(0)


if __name__ == "__main__":
    main()
