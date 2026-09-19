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
from datetime import datetime, timezone
from pathlib import Path

# Append-only log of blocks. Lets Claude detect when a dispatch (Bash, subagent
# prompt, etc.) was silently blocked — see memory/feedback_subagent_stuck_proactive.md.
# NEVER write prompt content here — only metadata (pattern types + counts).
_BLOCK_LOG = Path(__file__).parent / ".pii_blocks.log"


def _log_block(hits):
    """One-line marker per block. Metadata only — no PII content."""
    try:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        summary = ", ".join(f"{label}:{len(matches)}" for label, matches in hits)
        with open(_BLOCK_LOG, "a", encoding="utf-8") as f:
            f.write(f"{ts} | UserPromptSubmit | BLOCK | {summary}\n")
    except Exception:
        pass  # logging failure must never break the hook

# --- PII Patterns (adapted from DataFog datafog-python, MIT License) ---

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

# --- Allowlists (known-safe values that trip PII patterns) ---

_ALLOWED_EMAILS = {
    # YOUR OWN addresses go here. These are not third-party PII, they are yours,
    # and several are probably already public on your site footer.
    # "you@yourdomain.com",
    # "you@gmail.com",
}

# Whole domains that are YOUR OWN and therefore never third-party PII.
# A deliberate call: "exclude any @yourdomain.com emails from PII flagging."
#
# WHY this is a false-positive fix and NOT a posture downgrade (never downgrade a posture to reduce friction): this guard exists to stop OTHER
# people's contact details reaching the model provider. Addresses on your own
# business domain are his own information and several are published on his
# public site footer. Blocking them was over-blocking, not protection.
#
# ⚠ WHAT IT COST BEFORE THE FIX, and it is why this was worth changing: the guard
# also runs on SUBAGENT RESULT DELIVERY. A sweep agent read `a project file`
# (which carries `legal@` and similar on several lines), quoted a
# line back, and the entire result was dropped. TWICE. No error, no partial output,
# zero bytes — indistinguishable from an agent still running. It was diagnosed from the outside first.
#
# ⚠ DELIBERATELY NARROW. One domain, your own. Do NOT add a domain here to
# make an agent stop failing — a third party's address blocking a result is the
# guard WORKING. Redact at the emitter instead (redact at the emitter instead).
_ALLOWED_EMAIL_DOMAINS = {
    # "yourdomain.com",
}


# ★ MACHINE addresses are not PII, and are allowed regardless of domain.
# Added 2026-08-24 after `jobalerts-noreply@linkedin.com` silently killed a subagent
# result for the SECOND time in one session. Reported as: "pls fix the filter, this is
# getting old."
#
# WHY THIS IS A FALSE-POSITIVE FIX AND NOT A POSTURE DOWNGRADE (never downgrade a posture to reduce friction): this guard exists to stop OTHER PEOPLE'S
# contact details reaching the model provider. A no-reply address is nobody's contact detail.
# It cannot receive mail, it identifies no human, and it leaks nothing about anyone.
# Blocking it was over-blocking, exactly as the yourdomain.com domain rule already
# concluded for your own addresses.
#
# ⚠ WHAT IT COST: the guard also runs on SUBAGENT RESULT DELIVERY, so a hit drops the
# ENTIRE result with no error and zero bytes, indistinguishable from an agent still
# running. both were diagnosed from outside the session. Telling agents
# to "mask addresses" does NOT hold, which is why this is structural.
#
# ⚠ DELIBERATELY NARROW. Only local parts that are unambiguously automated. A named
# mailbox at any domain is still caught, which is the point. Do NOT add a pattern here
# to make an agent stop failing.
_MACHINE_LOCAL = re.compile(
    r'no[._-]?reply'
    r'|do[._-]?not[._-]?reply'
    r'|mailer[._-]?daemon'
    r'|^postmaster$'
    r'|^bounces?$'
    r'|^notifications?$'
    r'|^automated$',
    re.IGNORECASE,
)


def _email_allowed(addr):
    """True if this address is individually allowlisted, on an owned domain, or is a
    machine (no-reply) address that identifies no person."""
    a = addr.lower()
    if a in _ALLOWED_EMAILS:
        return True
    local, _, domain = a.rpartition("@")
    if local and _MACHINE_LOCAL.search(local):
        return True
    return domain in _ALLOWED_EMAIL_DOMAINS

_ALLOWED_IPS = {
    # IPs of machines you own. Your own server address is not PII.
    # "203.0.113.10",   # example: my VPS
}

# --- URL false-positive suppression ---
# Some URLs carry opaque numeric identifiers that are structurally identical to a
# bare 10-digit phone number. Mask the digits inside these known-safe URLs ONLY, so
# a real phone number typed anywhere else in the same message is still caught. Same
# intent as the SSN hex-agent-ID filter in scan(): reduce false positives, do not
# widen what is allowed. Digits only are masked, so an email in a query param is
# still detected.
#
# Born 2026-07-27: Google Docs/Drive/Sheets `?gid=1259827479#gid=1259827479`
# (a 10-digit sheet tab id) blocked a paste as "phone".
#
# Extended 2026-08-08 to LinkedIn: job-posting permalinks are
# `linkedin.com/jobs/view/<10-digit id>`, which the phone pattern matches every
# time. Hit in practice when pasting a job link; the id had to be hand-mangled.
#
# ★ GENERALISED 2026-08-24 on a deliberate call, from a two-host allowlist to ANY URL.
# His words: "can we pls exclude phone numbers if they are part of a url? eventhough
# it's not even a phone number." Opaque numeric ids in URL paths and query strings
# are ubiquitous (job ids, sheet tab ids, order ids, asset ids, message ids) and a
# host allowlist can only ever chase them one host at a time. It had already been
# extended once and was about to be extended again.
#
# ⚠ THIS IS A REAL WIDENING, SO IT CARRIES A CARVE-OUT. Some URLs legitimately
# CARRY a phone number as their payload, and those must still be caught: `tel:`,
# `sms:`, `callto:`, `wa.me/<number>`, Twilio endpoints, and any query parameter
# named phone/tel/mobile/msisdn/number. Masking those would turn this from a
# false-positive fix into an actual hole. _PHONE_URL is checked FIRST and wins.
#
# ⚠ WHAT THIS DOES NOT FIX, stated so nobody re-derives it as a bug: the 2026-08-24
# block that prompted the change was NOT a URL. A subagent abbreviated a LinkedIn
# permalink to `(listing URL .../4457053864/)`, stripping the host. A bare digit run
# between slashes is indistinguishable from a phone number and is deliberately still
# caught. The fix for that is the agent prompt (always emit full URLs, never
# abbreviate), not a looser matcher.
_PHONE_URL = re.compile(
    r'(?:tel|sms|callto|fax):'
    r'|(?:https?://)?(?:www\.)?(?:wa\.me|api\.twilio\.com|t\.me)/'
    r'|[?&](?:phone|tel|telephone|mobile|msisdn|number|contact)=',
    re.IGNORECASE,
)

# Two shapes, because bare scheme-less pastes are common and the previous
# two-host rule already accepted them. Both require a real host and a path, so a
# bare digit run or an abbreviated `.../123/` fragment never qualifies.
_SAFE_URL = re.compile(
    r'(?:https?://|www\.)[^\s<>"\')]+'          # explicit scheme, or www. host
    r'|(?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s<>"\')]+',  # host.tld/path, no scheme
    re.IGNORECASE,
)


def _mask_safe_url_digits(text):
    """Replace digits with '#' inside URLs, so opaque numeric ids do not read as
    phone numbers. URLs that legitimately carry a phone number are left alone, and
    non-URL text is never touched."""
    def _mask(m):
        url = m.group(0)
        if _PHONE_URL.search(url):
            return url                      # phone-bearing URL: leave it detectable
        return re.sub(r'\d', '#', url)
    return _SAFE_URL.sub(_mask, text)


# --- Labelled numeric-id suppression (added 2026-09-18) ---
# A job/req/order id written in PLAIN TEXT, outside any URL, e.g. "reached via
# LinkedIn job 4462868753". The URL carve-out above cannot see it because there is
# no URL. Hit in practice when pasting a prompt containing such an id.
# ⚠ Deliberately narrow, two conditions, both required:
#   1. the digits directly follow an ID LABEL (job, req, posting, order, ticket,
#      id, #, ...), with at most an optional "id"/"no." and ":"/"#" between; and
#   2. the run is UNFORMATTED: 8+ contiguous digits, no dashes/dots/spaces/parens.
# So "job 650-555-1234" or "call 6505551234" is still caught. Phone-shaped labels
# (phone, tel, mobile, cell, call, text) are not in the list and never will be.
_LABELLED_ID = re.compile(
    r'(?i)\b(?:job|jobs|req|requisition|posting|listing|order|ticket|case|invoice'
    r'|application|app|candidate|ref|reference|id|li|linkedin|num)'
    r'(?:\s*(?:id|no\.?|number|#))?\s*[:#]?\s*'
    r'(?<![\d-])(\d{8,})(?![\d-])'
)


def _mask_labelled_ids(text):
    return _LABELLED_ID.sub(lambda m: m.group(0)[:m.start(1)-m.start(0)] + '#' * len(m.group(1)), text)


def scan(text):
    text = _mask_safe_url_digits(text)
    text = _mask_labelled_ids(text)
    found = []
    for label, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            if label == "email":
                matches = [m for m in matches if not _email_allowed(m)]
            elif label == "IP address":
                matches = [m for m in matches if m not in _ALLOWED_IPS]
            elif label == "SSN":
                # Filter false positives from hex agent IDs and other non-SSN digit sequences
                # Real SSNs are XXX-XX-XXXX with dashes; bare 9-digit runs in hex contexts are noise
                matches = [m for m in matches if '-' in str(m)]
            if matches:
                found.append((label, matches))
    return found


def selftest():
    """Exercise scan() DIRECTLY as a library call against pii_check_cases.json.
    No hook plumbing, no stdin, nothing to bypass: the selftest and the live hook
    run the same scan(). Per RULES-OF-ENGAGEMENT, a selftest on a different path
    than the control is worse than none."""
    import pathlib
    cases = json.loads((pathlib.Path(__file__).parent / 'pii_check_cases.json')
                       .read_text(encoding='utf-8'))['cases']
    bad = 0
    for c in cases:
        labels = [lbl for lbl, _ in scan(c['text'])]
        got = 'clean' if not labels else ','.join(sorted(set(labels)))
        ok = (got == c['expect'])
        if not ok:
            bad += 1
        print(f"{'PASS' if ok else 'FAIL'}  {c['name']}")
        print(f"        expect={c['expect']} got={got}")
    print(f"{len(cases) - bad}/{len(cases)} green")
    return 1 if bad else 0


def main():
    if '--selftest' in sys.argv:
        sys.exit(selftest())
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
        _log_block(hits)
        lines = ["[PII WARNING] Sensitive data detected before sending to Anthropic:"]
        for label, matches in hits:
            lines.append(f"  {label}: {', '.join(str(m) for m in matches[:3])}")
        lines.append("Consider referencing a local file instead. See trust-config.md.")
        sys.stderr.buffer.write(("\n".join(lines) + "\n").encode("utf-8"))
        sys.exit(2)  # exit 2 = block with message shown to user

    sys.exit(0)


if __name__ == "__main__":
    main()
