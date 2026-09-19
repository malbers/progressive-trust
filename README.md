# Progressive Trust

A framework for defining how AI systems earn the right to act on your behalf, plus the hooks
that actually enforce it.

**Last updated:** September 2026 · see [CHANGELOG.md](./CHANGELOG.md)

---

## The idea

Most AI assistants operate on an assumption of autonomy. They read your files, send messages,
take actions, and ask forgiveness later. That is the wrong model.

Progressive trust works the other way. The AI starts with limited access and earns more over
time, through explicit grants, demonstrated reliability, and transparency about what it is
doing. The same way you would onboard a new employee. You do not hand them the keys on day
one.

The framework is simple: define what the AI can do without you, what always requires
approval, what data it can touch, and what it can never do regardless of context. Write it
down. Then enforce it in tooling, so it is not just a document.

---

## "So does the AI have my email password?"

This is the first question everyone asks, and it deserves a direct answer.

**No. Your tokens never leave your machine.**

Credentials live in one local directory, outside every repo:

```
~/.secrets/            # chmod 700, never committed, never synced
  github_token
  gmail_oauth.json
```

The AI references a secret **by name**. A local helper script reads the file, makes the call,
and masks the value in everything it prints. The model provider sees the *name* of the secret
and the *result* of the call. It never sees the secret.

The practical shape:

```bash
# the credential is never in the command, so it is never in the payload
python3 scripts/authed_call.py --secret-name github_token --auth token \
    --url https://api.github.com/user
```

That is the whole mechanism. Everything else in this repo is about making sure it stays true
when you are not watching.

---

## Progressive permissions, applied to accounts

The trust tiers are the philosophy. This is the part you use on a Tuesday.

**Separate READ from DRAFT from ORGANIZE from SEND from DELETE, and grant them one at a
time, per account.** Most integrations offer them as a bundle. Take the bundle apart.

| Rung | Capability | What it means |
|---|---|---|
| 1 | **Read** | The AI can see the content. Nothing changes, nothing leaves. |
| 2 | **Draft** | It can compose, and the draft waits where you will see it. |
| 3 | **Organize** | Archive, label, mark read. Reversible, affects only you. |
| 4 | **Send** | It can talk to other people as you. |
| 5 | **Delete** | Destructive. Usually no reason to grant it at all. |

Start at rung 1. Move one rung at a time. Never skip to 4.

Email is where this matters most, because rung 4 means the AI can speak to your colleagues
and clients in your name. Run different accounts at different rungs on purpose:

```
work-primary@   read + draft + organize + send-with-per-message-approval
personal@       read + draft + organize, NO send, NO hard-delete
secondary@      read + draft only
archive@        read only
```

Two things that will trip you up, both covered in
[`trust-config.md` §5](./trust-config.md):

- **An OAuth scope and your actual enforcement are different layers.** A scope may permit
  sending even when your intent is "organize only". Know whether "no send" is held by the
  scope, by your wrapper script, or only by an instruction in a config file. The last one is
  a hope, not a control.
- **Scope is not per-resource access.** An app can hold calendar-write and still be refused
  on a specific calendar. Use that: let the assistant create events on *its own* calendar and
  invite you. Your accept becomes the approval gate.

---

## The config file

[`trust-config.md`](./trust-config.md) is a template to adapt. It covers data classification,
credential handling, action permissions, trust tiers, progressive account permissions,
workspace boundaries, hard rules, audit trail, tool onboarding, and enforcement.

Adapt it, version-control it, load it at the start of every AI session.

---

## Enforcement: what actually ships here

The config defines the rules. These enforce them.

| Control | Hook type | What it does |
|---|---|---|
| [`hooks/pii_check.py`](./hooks/pii_check.py) | UserPromptSubmit | Scans outgoing prompts for personal data and credentials, blocks before transmission |
| [`hooks/pii_check_inbound.py`](./hooks/pii_check_inbound.py) | PostToolUse | Flags credentials and personal data in tool output. Advisory only, and see the honest limit below |
| [`hooks/token_leak_guard.py`](./hooks/token_leak_guard.py) | PreToolUse (Bash) | Denies commands that would read-and-echo a secret, or that carry an inline credential |
| [`hooks/state_file_guard.py`](./hooks/state_file_guard.py) | PreToolUse (Write/Bash) | Blocks whole-file writes to memory and state files, forces Edit |
| [`scripts/authed_call.py`](./scripts/authed_call.py) | helper | Authenticated HTTP with the secret by name, masked at the print site |

**Every guard ships with a selftest and a fixture file. Run them before you trust them:**

```bash
python3 hooks/token_leak_guard.py --selftest     # 29 cases
python3 hooks/state_file_guard.py --selftest     # 24 cases
python3 hooks/pii_check.py --selftest            # 32 cases
python3 scripts/authed_call.py --selftest        # 10 cases
```

No real credentials appear in any fixture.

### Installing

Copy the hooks somewhere stable and register them in `.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {"matcher": "", "hooks": [
        {"type": "command", "command": "python3 /abs/path/hooks/pii_check.py"}
      ]}
    ],
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [
        {"type": "command", "command": "python3 /abs/path/hooks/token_leak_guard.py"}
      ]},
      {"matcher": "Write|Edit|Bash", "hooks": [
        {"type": "command", "command": "python3 /abs/path/hooks/state_file_guard.py"}
      ]}
    ],
    "PostToolUse": [
      {"matcher": "Bash|WebFetch", "hooks": [
        {"type": "command", "command": "python3 /abs/path/hooks/pii_check_inbound.py"}
      ]}
    ]
  }
}
```

Every hook fails open. If a script errors, it exits 0 and your workflow continues. A guard
that breaks your work gets uninstalled, and an uninstalled guard protects nothing.

**Restart your session after wiring.** A hook edit is inert until then. You can read the
settings file, see the hook listed, and still be running a process that loaded none of it.

---

## About the `$(cat ...)` pattern

Earlier versions of this repo recommended this, and a lot of guides still do:

```bash
curl -H "Authorization: Bearer $(cat ~/.secrets/token)" https://api.example.com
```

**It is half right, and the half it gets wrong is the half that leaks.**

What it gets right: the shell expands the substitution locally, so only the literal text is
transmitted. The token is not in the **input** payload. That part of the original advice was
correct and it is worth saying so plainly.

What it misses: the **output** side. `curl` prints the response. If the endpoint echoes the
token, redirects with it in a URL, or returns it in an error body, the value is in the
transcript anyway. A hook that inspects commands sees the command, never the output.

Every real credential leak we have seen came from output, not input. The specific shape: an
agent gets blocked reading a secret, writes its own small script to read it, and that script
prints the value. The guard worked exactly as written and the secret still leaked.

`scripts/authed_call.py` owns the print site and masks there, which closes both sides.

---

## The limit, stated rather than hidden

**A script that reads a credential and prints it defeats every guard in this repo.**

Claude Code's `PostToolUse` hooks run after the tool has executed, cannot modify or suppress
output, and have no block decision available. Only `PreToolUse` can block, and it never sees
output. This is a platform limit, not a roadmap item, and pretending otherwise would be
worse than the gap.

Same for the response side: the outbound PII hook scans what *you* type, not what the model
says back. If the AI reads a file containing someone's address and quotes it, that reaches
the provider even though you never typed it.

The mitigation for both is structural: mask at the print site, and refer to other people's
data by description rather than value. `pii_check_inbound.py` exits 0 because that is the
most it can do. Making it "blocking" would be theatre.

**A control you believe is active but is not is worse than one you know is absent**, because
it stops getting scrutiny. That is why these limits are in the README and not a footnote.

---

## One more thing that will surprise you

**Writing about security work trips the security controls.** A commit message describing a
credential fix, a test fixture holding a fake token, a search whose pattern names a secrets
directory: all of these fire `token_leak_guard`, because it reads the command string and
cannot tell a command that *reads* a credential from one whose text merely *mentions* one.

That is working as specified. The fix is always the same: **move the text into a file and
pass the path.** `git commit -F <path>`. Test case into the fixture. Repo search via your
agent's file-search tool rather than shell grep.

Never rephrase the string to slip past the matcher. That is evasion, not a fix.

And do not allowlist a whole verb to reduce friction. `grep -r` against a secrets directory
prints secrets. The remedy for friction is never "block less", it is **make the sanctioned
path faster to find than the workaround**, which is why these hooks print the escape hatch in
the denial message itself.

---

## Related

- [claude-memory-context](https://github.com/malbers/claude-memory-context) - persistent
  memory across sessions, and the state files `state_file_guard.py` protects
- [claude-quickstarter](https://github.com/malbers/claude-quickstarter) - start here if you
  are setting up Claude as an operating partner for the first time

---

## Background

Built while running Claude as a full-time operating layer across two businesses. What started
as a personal config file turned into a framework worth sharing. It has been used with AI
cohorts, startup founders and senior operators learning to work with agentic AI. The trust
tier model in particular tends to change how people think about what "AI autonomy" means in
practice.

PII patterns adapted from [DataFog datafog-python](https://github.com/DataFog/datafog-python)
(MIT). Token patterns, guards and helper scripts are original.

## If you use this

Free to use and adapt under the [MIT License](./LICENSE). If it is useful, a note back on
what you changed is genuinely welcome.

---

*Michael Albers, [Albers Advisory](https://albersadvisory.biz) ·
[LinkedIn](https://www.linkedin.com/in/malbers/)*
