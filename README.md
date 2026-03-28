# Progressive Trust

A framework for defining how AI systems earn the right to act on your behalf.

**Last updated:** March 2026

### Recent updates
- **Inbound PII hook** (`hooks/pii_check_inbound.py`) — PostToolUse scanner catches PII in tool output before Claude echoes it back. Advisory-only, allowlist-driven, never blocks workflow.
- **Shell command credential rule** (trust-config v1.2) — command strings are API payloads too; file-based injection pattern added with enforcement hook roadmap.
- **Outbound PII hook** (`hooks/pii_check.py`) — UserPromptSubmit scanner, 11 pattern types, blocks before transmission to provider.

---

## The Idea

Most AI assistants operate on an assumption of autonomy — they read your files, send messages, take actions, and ask forgiveness later. That's the wrong model.

Progressive trust works the other way. AI starts with limited access and earns more over time, through explicit grants, demonstrated reliability, and transparency about what it's doing. The same way you'd onboard a new employee — not hand them the keys on day one.

The framework is simple: define what AI can do without you, what always requires approval, what data it can touch, and what it can never do regardless of context. Write it down. Then enforce it in your tooling so it isn't just a document.

---

## The Config File

[`trust-config.md`](./trust-config.md) is a template you can adapt to your own setup. It covers:

- Data classification — what stays local, what can go to the cloud, what never leaves your machine
- Action permissions — what's autonomous vs. what always requires your approval
- Trust tiers — how new tools and integrations earn access over time
- Hard rules — the non-negotiables, regardless of trust level
- Audit trail — how to keep a log of what AI does on your behalf
- Onboarding new tools — questions to ask before granting access

Adapt it, version-control it, load it at the start of every AI session. The philosophy is the easy part — the value comes from enforcement.

---

## Enforcement: The PII Hook

The config file defines the rules. The hooks enforce them.

[`hooks/pii_check.py`](./hooks/pii_check.py) is a Claude Code `UserPromptSubmit` hook that scans every outgoing message before it reaches Anthropic. If it finds sensitive data, it blocks the prompt and tells you what it caught.

**What it detects:**

| Category | Patterns |
|----------|----------|
| Personal | Email, phone (US + international), SSN (with and without dashes) |
| Financial | Credit card numbers (Visa, Mastercard, Amex) |
| Network | IPv4 addresses |
| Tokens & secrets | GitHub tokens, AWS access keys, Anthropic keys, OpenAI keys, JWTs, private key blocks |

PII patterns adapted from [DataFog datafog-python](https://github.com/DataFog/datafog-python) (MIT License). Token patterns are original.

**Installing the hook:**

1. Copy `hooks/pii_check.py` somewhere on your machine (e.g. `~/.claude/hooks/pii_check.py`)
2. Add to your Claude Code settings (`.claude/settings.json`):

```json
{
  "hooks": {
    "UserPromptSubmit": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "python /absolute/path/to/hooks/pii_check.py"
      }]
    }]
  }
}
```

3. No restart needed — the hook runs fresh on every prompt.

**Testing it:**

Paste a fake token into your next Claude Code prompt:

```
my test token is ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890
```

You should see:

```
[PII WARNING] Sensitive data detected before sending to Anthropic:
  GitHub token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890
Consider referencing a local file instead. See trust-config.md.
```

The hook always fails open — if the script errors for any reason, it exits 0 and lets the prompt through. It never silently breaks your workflow.

---

## Enforcement: Inbound PII Hook

[`hooks/pii_check_inbound.py`](./hooks/pii_check_inbound.py) is a Claude Code `PostToolUse` hook that scans tool output (Bash, WebFetch) before Claude incorporates it into a response. The outbound hook catches what you type. This hook catches what comes back.

**Why it matters:** tool output is part of the API payload. If Claude reads a curl response containing a token and quotes it in its reply, that token goes to the AI provider — even if you never typed it.

**How it works:** advisory-only. When sensitive data is found, it injects a system message telling Claude to reference the data by description rather than value. It never blocks or interrupts your workflow.

**Allowlist:** create `~/.secrets/pii_allowlist.txt` with one value per line. Known-safe values (your own email, service addresses) are silently skipped, preventing the hook from becoming noise.

```
# ~/.secrets/pii_allowlist.txt
your-own@email.com
noreply@someservice.com
```

**Installing the hook:**

Add to your Claude Code settings (`.claude/settings.json`):

```json
{
  "hooks": {
    "PostToolUse": [{
      "matcher": "Bash|WebFetch",
      "hooks": [{
        "type": "command",
        "command": "python /absolute/path/to/hooks/pii_check_inbound.py"
      }]
    }]
  }
}
```

**Patterns detected:** same 10 types as the outbound hook (email, phone, SSN, credit card, GitHub token, AWS key, Anthropic key, OpenAI key, JWT, private key) — IP addresses excluded to avoid noise from server addresses in shell output.

---

## Enforcement: Shell Command Credentials

The PII hook catches what you type. It doesn't catch credentials that appear inside shell commands Claude runs on your behalf.

When an AI executes a bash command, the full command string is transmitted to the provider as part of the tool call payload. An inline credential in a command is just as exposed as typing it directly in the chat window.

**The pattern to avoid:**
```bash
# The token travels to Anthropic as part of the tool call
curl -H "Authorization: Bearer ghp_abc123..." api.github.com
```

**The pattern to use:**
```bash
# The token stays local — only the file path appears in the payload
curl -H "Authorization: Bearer $(cat ~/.secrets/github_token)" api.github.com
```

Keep all tokens and secrets in a local secrets directory (e.g. `~/.secrets/` or `~/.claude/.secrets/`). Reference them by path in any command the AI runs. The same applies to `--password`, `--token`, `--api-key` flags, and inline env vars like `API_KEY=secret ./script.sh`.

A `PreToolUse` hook on Bash commands can automate this — scanning for inline credential patterns before the command runs and warning you to use file-based injection instead. The rule is in the config; the hook makes it enforceable.

---

## Background

I built this after spending the last several months running Claude as a full-time operating layer across two businesses. I needed a way to be explicit about what it could and couldn't do — not as a vague preference, but as a documented, enforced policy. What started as a personal config file turned into a framework I now share with other practitioners.

I've used this with AI cohorts, startup founders, and senior operators learning to work with agentic AI. The trust tier model in particular tends to change how people think about what "AI autonomy" actually means in practice.

If you want to go deeper — the hooks that enforce this in tooling, the approval flows, what it looks like running in production — feel free to reach out.

---

## If You Use This

This framework is free to use and adapt. If it's useful, a shout-out is appreciated — tag me on [LinkedIn](https://www.linkedin.com/in/malbers/) or drop me a note at michael@albersadvisory.biz. I'd genuinely like to know how you've adapted it.

---

*Michael Albers — [Albers Advisory](https://albersadvisory.biz)*
