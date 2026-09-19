#!/usr/bin/env python3
"""token_leak_guard.py - PreToolUse hook on Bash. Blocks commands that could leak credentials.

WHAT THIS IS FOR
When an AI agent runs a shell command on your behalf, the full command string is sent to the
model provider as part of the tool-call payload. That makes two different things dangerous:

  1. READ-AND-ECHO - a command whose job is to print a secret it does not itself contain.
     `cat ~/.secrets/api_token`, `git remote get-url origin` (if the remote URL has an
     embedded token), `env | grep KEY`, `gh auth token`.

  2. INLINE CREDENTIAL - a literal secret pasted into the command. That value lands in the
     payload verbatim, exactly as if you had typed it into the chat window.

This hook inspects the command string before execution and denies on both shapes.

WHAT IT CANNOT DO, STATED PLAINLY
There is a third shape it will never catch: a script that reads a secret from disk and
PRINTS it. This hook sees the command, never the output. A one-line script that opens a
credentials file and echoes the value passes this guard cleanly and puts the secret in the
transcript anyway.

That is not a bug to be fixed later. Claude Code's PostToolUse hooks run after the tool has
already executed and cannot modify or suppress output, so no hook can close it. The mitigation
is structural: mask at the print site, inside the script that does the reading. Keep that in
mind before you conclude this hook makes you safe.

INSTALL
Copy to your hooks directory and register as a PreToolUse hook matching Bash:

    {
      "hooks": {
        "PreToolUse": [{
          "matcher": "Bash",
          "hooks": [{"type": "command", "command": "python3 /abs/path/hooks/token_leak_guard.py"}]
        }]
      }
    }

VERIFY IT WORKS
    python3 hooks/token_leak_guard.py --selftest

Exit 0 means every case in token_leak_guard_cases.json behaves as declared. The fixture
contains no real credentials. See the note above run_selftest() for why this matters more
than it looks.
"""

import json
import re
import sys

# Commands whose entire job is to print a file's contents. Covering only `cat` is the
# classic mistake: `head ~/.secrets/x` walks straight past a guard that stops
# `cat ~/.secrets/x`. The trailing group eats flags and their numeric values, so
# `head -c 400 <file>` is caught too.
_READ = r"\b(?:cat|bat|head|tail|less|more|strings|xxd|od|nl|tac|rev|base64)\s+(?:(?:-\S+|\d+)\s+)*"

# Paths that only ever hold credentials. Safe to widen across every reader above, because
# no ordinary source file lives at these locations.
#
# Deliberately NOT extended to `*_token*` / `*_key*` FILENAME patterns. Those are name
# fragments that collide with ordinary source files (`api_key_helper.py`), and widening
# them trades a rare false negative for a constant false positive on routine code reading.
# A guard that fires on normal work gets worked around, and the workaround is usually worse
# than what you were guarding against.
#
# `.git/config` is in this list for a specific reason: a git remote can carry a plaintext
# token, which is why `git remote get-url` is blocked below. But that only blocked the
# porcelain reader. `cat .git/config` printed the same token and passed clean. Widening the
# READER list while leaving the LOCATION list short is the most common way this class of
# guard stays broken.
#
# `.claude.json` and `.claude/settings.json` hold MCP server blocks, and an http MCP entry
# carries its bearer token in a plaintext headers.Authorization value. They are config files
# nobody thinks of as credential stores, which is exactly why they get read casually.
_SECRET_LOC = (r"(?:/\.?secrets?/|\.secrets|/credentials/|\.netrc|\.npmrc|\.pypirc"
               r"|\.git[\\/]config|\.git[\\/]credentials"
               r"|\.claude\.json|\.claude[\\/]settings(?:\.local)?\.json)")

# Matched case-insensitively against the full command string. (regex, human label).
BLOCK_PATTERNS = [
    # git remote URL exposure - a remote can carry an embedded token
    (r"\bgit\s+remote\s+get-url\b", "git remote get-url"),
    (r"\bgit\s+remote\s+-v\b", "git remote -v"),
    (r"\bgit\s+config\s+--get\s+remote\.origin\.url\b", "git config --get remote.origin.url"),
    # reading .env files (but not .env.example / .env.template / .env.sample)
    (_READ + r"['\"]?\.env['\"]?\s*$", "read .env"),
    (_READ + r"['\"]?\.env[^e][^\s]*", "read .env* (non-example)"),
    # reading anything in a credentials LOCATION, via any reader above
    (_READ + r"['\"]?[^\s]*" + _SECRET_LOC + r"[^\s]*", "read a credentials-location file"),
    # secret-flavored FILENAMES - `cat` only, see the _SECRET_LOC note above
    (r"\bcat\s+['\"]?[^\s]*\.secret[^\s]*", "cat *.secret*"),
    (r"\bcat\s+['\"]?[^\s]*_token[^\s]*", "cat *_token*"),
    (r"\bcat\s+['\"]?[^\s]*_key[^\s]*", "cat *_key*"),
    # Inline interpreter (python -c, node -e, ruby -e) opening a credentials file.
    #
    # This hook sees the COMMAND, never stdout, so it cannot know whether the value gets
    # printed. But the only reason to read a secret inside a throwaway one-liner is to look
    # at it. This is the single most valuable pattern in the list: it is the shape an agent
    # reaches for after being blocked twice, and "agent writes its own script to read the
    # key" is the documented way a working guard still ends in a leak.
    #
    # The [rbfuRBFU]{0,2} allows for a Python raw/byte/f-string prefix between `open(` and
    # the quote - open(r'C:\Users\...'). Windows paths make r'...' the natural way to write
    # this, so omitting it leaves a likely gap rather than an exotic one.
    #
    # Quantifiers are bounded on purpose. Never leave an unbounded quantifier in a pattern
    # that may run against a very long single-line input.
    (r"-(?:c|e)\s+.{0,300}?(?:open|read_text|readFileSync|File\.read|IO\.read)"
     r"\s*\(?\s*[rbfuRBFU]{0,2}['\"][^'\"]{0,200}"
     + _SECRET_LOC,
     "inline interpreter reading a credentials file"),
    # env / printenv exposure
    (r"(?:^|\s)env\s*$", "env (bare)"),
    (r"\benv\s+\|.*grep.*(?:key|token|secret|pass|api|auth|credential)", "env | grep <cred>"),
    (r"\bprintenv\s+[A-Z_]*(?:KEY|TOKEN|SECRET|PASS|API|AUTH|CREDENTIAL)[A-Z_]*", "printenv <cred var>"),
    # CLI tools that print a token by design
    (r"\bgh\s+auth\s+token\b", "gh auth token"),
]

# ---------------------------------------------------------------------------
# Inline-credential patterns.
#
# The list above covers READ-AND-ECHO: commands that would print a secret they do not
# contain. This second list covers a literal credential pasted INTO the command string.
#
# Every pattern deliberately excludes shell expansion, so a command that reads a value
# from an already-exported environment variable passes untouched. Only literal values
# are blocked.
# ---------------------------------------------------------------------------

# Shared negative lookahead: reject the match if the value begins with a shell expansion
# or is empty.
_NOT_EXPANSION = r"(?!\$|`|\s|$)"

INLINE_CRED_PATTERNS = [
    # --- provider token prefixes appearing literally in the command ---
    (r"\bghp_[A-Za-z0-9]{16,}", "GitHub personal access token (ghp_)"),
    (r"\bgh[ousr]_[A-Za-z0-9]{16,}", "GitHub token (gho_/ghu_/ghs_/ghr_)"),
    (r"\bgithub_pat_[A-Za-z0-9_]{20,}", "GitHub fine-grained PAT"),
    (r"\bnfp_[A-Za-z0-9]{16,}", "Netlify personal access token (nfp_)"),
    (r"\bsk-ant-[A-Za-z0-9\-_]{16,}", "Anthropic API key (sk-ant-)"),
    (r"\bsk-[A-Za-z0-9]{32,}", "OpenAI-style secret key (sk-)"),
    (r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", "Slack token (xox*-)"),
    (r"\bAIza[0-9A-Za-z_\-]{35}", "Google API key (AIza)"),
    (r"\bglpat-[A-Za-z0-9\-_]{16,}", "GitLab PAT (glpat-)"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "PEM private key block"),
    # --- database URIs carrying inline credentials ---
    (r"\b(?:postgres|postgresql|mysql|mongodb)(?:\+srv)?://[^:\s/]+:[^@\s]+@",
     "database URI with inline credentials"),
    # --- credential-bearing flags with a literal value ---
    (r"--(?:password|passwd|token|api[-_]?key|secret|auth[-_]?token)[=\s]+" + _NOT_EXPANSION + r"['\"]?[^\s'\"]{6,}",
     "--password/--token/--api-key with a literal value"),
    # --- Authorization header with a literal bearer/basic value ---
    (r"[Aa]uthorization:\s*(?:Bearer|Basic|token)\s+" + _NOT_EXPANSION + r"['\"]?[A-Za-z0-9._\-]{16,}",
     "Authorization header with a literal credential"),
    # --- inline env-var assignment with a literal value ---
    (r"\b[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|AUTH)[A-Z0-9_]*=" + _NOT_EXPANSION + r"['\"]?[^\s'\"]{8,}",
     "inline VAR=<literal secret> assignment"),
]

# (pattern, replacement) pairs used to scrub any command echoed back in a denial message.
#
# Without this, blocking an inline-credential command would print the credential into the
# transcript, defeating the entire point of the block. Replacements keep the surrounding
# context (flag name, var name, URI scheme) so the message still says WHAT was wrong.
_RED = "***REDACTED***"

REDACT_PATTERNS = [
    (r"\bghp_[A-Za-z0-9]{16,}", _RED),
    (r"\bgh[ousr]_[A-Za-z0-9]{16,}", _RED),
    (r"\bgithub_pat_[A-Za-z0-9_]{20,}", _RED),
    (r"\bnfp_[A-Za-z0-9]{16,}", _RED),
    (r"\bsk-ant-[A-Za-z0-9\-_]{16,}", _RED),
    (r"\bsk-[A-Za-z0-9]{32,}", _RED),
    (r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", _RED),
    (r"\bAIza[0-9A-Za-z_\-]{35}", _RED),
    (r"\bglpat-[A-Za-z0-9\-_]{16,}", _RED),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "-----BEGIN PRIVATE KEY----- " + _RED),
    # db URI: keep the scheme, drop user:pass
    (r"\b((?:postgres|postgresql|mysql|mongodb)(?:\+srv)?://)[^:\s/]+:[^@\s]+@", r"\1" + _RED + "@"),
    # keep the flag name, drop the value
    (r"(--(?:password|passwd|token|api[-_]?key|secret|auth[-_]?token)[=\s]+)(?!\$|`)['\"]?[^\s'\"]{6,}",
     r"\1" + _RED),
    # keep the scheme word, drop the credential
    (r"([Aa]uthorization:\s*(?:Bearer|Basic|token)\s+)(?!\$|`)['\"]?[A-Za-z0-9._\-+/=]{16,}",
     r"\1" + _RED),
    # keep the var name, drop the value
    (r"\b([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|AUTH)[A-Z0-9_]*=)(?!\$|`)['\"]?[^\s'\"]{8,}",
     r"\1" + _RED),
]


def redact(cmd: str) -> str:
    """Scrub credential-shaped substrings before a command is echoed back."""
    out = cmd
    for pat, repl in REDACT_PATTERNS:
        out = re.sub(pat, repl, out)
    return out


# Allowlist: if the command matches any of these, skip blocking.
#
# Keep this list tiny and specific. Do NOT allowlist a whole verb like `grep` or
# `git commit` to reduce friction. `grep -r` against a secrets directory prints secrets.
# The remedy for friction is never "block less", it is "make the sanctioned path faster to
# find than the workaround" - which is why the escape hatch is printed in the denial
# message rather than left in documentation.
ALLOW_PATTERNS = [
    r"\.env\.example",
    r"\.env\.template",
    r"\.env\.sample",
]


def check_allowlist(cmd: str) -> bool:
    for pat in ALLOW_PATTERNS:
        if re.search(pat, cmd, re.IGNORECASE):
            return True
    return False


def decide(cmd: str):
    """THE full decision: allowlist first, then pattern match.

    main() and --selftest both route through this on purpose. An earlier version had the
    selftest call find_match() directly, which skipped the allowlist and confidently
    reported a false positive that production did not actually have.

    A selftest that exercises a different code path than the control is worse than no
    selftest: it produces trustworthy-looking numbers about behaviour that is not the real
    behaviour. If you adapt this hook, keep the single-entry-point shape.
    """
    if check_allowlist(cmd):
        return None
    return find_match(cmd)


def find_match(cmd: str):
    for pat, label in BLOCK_PATTERNS:
        if re.search(pat, cmd, re.IGNORECASE | re.MULTILINE):
            return pat, label
    # Inline-credential patterns are matched CASE-SENSITIVELY. Token prefixes (ghp_,
    # sk-ant-, AIza) and env-var names are case-bearing, and folding case would make the
    # VAR=<literal> pattern fire on ordinary lowercase flags.
    for pat, label in INLINE_CRED_PATTERNS:
        if re.search(pat, cmd, re.MULTILINE):
            return pat, label
    return None


def block(cmd: str, label: str) -> None:
    # Redact BEFORE truncating. The denial message goes into the transcript, and for the
    # inline-credential patterns the secret is in the command itself.
    safe = redact(cmd)
    preview = safe[:200] + ("..." if len(safe) > 200 else "")
    reason = (
        f"TOKEN LEAK GUARD: blocked Bash command.\n\n"
        f"Command: {preview}\n"
        f"Match: {label}\n\n"
        f"This command could put a credential into the transcript sent to the model provider.\n\n"
        f"WHAT TO DO INSTEAD:\n"
        f"  - Is this text only *mentioning* a credential shape, not reading one?\n"
        f"    A commit message describing security work, a test fixture, a grep pattern that\n"
        f"    names a credentials path, a doc example. This guard reads the COMMAND STRING\n"
        f"    and cannot tell those apart from a real read, so it fires. That is working as\n"
        f"    specified, not a false positive to be tuned away.\n"
        f"    FIX: move the text into a FILE and pass the path.\n"
        f"      commit message -> write the file, then `git commit -F <path>`\n"
        f"      test case      -> add it to token_leak_guard_cases.json, run --selftest\n"
        f"      repo search    -> use your agent's file-search tool, not Bash grep\n"
        f"    Do NOT rephrase or obfuscate the string to slip past the matcher. That is\n"
        f"    evasion, not a fix.\n"
        f"  - For a git remote: `git branch -vv`\n"
        f"  - For env vars: python3 -c \"import os; print('set' if os.environ.get('VAR') else 'unset')\"\n"
        f"  - For .env: `grep -v -E '=.+' .env` shows keys without values\n"
        f"  - For an authed API call, or anything else needing a real credential:\n"
        f"      python3 scripts/authed_call.py --secret-name <name> --url <url>\n"
        f"    The flag is --secret-name, not --secret: `--secret <value>` is itself an\n"
        f"    inline-credential shape this guard blocks, and rightly so. The helper reads the\n"
        f"    secret itself and masks it in everything it prints, including HTTP error bodies.\n\n"
        f"NOTE: the `$(cat ~/.secrets/<file>)` command-substitution idiom is deliberately\n"
        f"blocked here. It was never an input-side leak - the shell expands it locally, so\n"
        f"only the literal text is transmitted. It is blocked because it does nothing for the\n"
        f"OUTPUT side, which is where real leaks come from, and because it trains the habit of\n"
        f"pointing commands at credential files. Use the helper above instead.\n\n"
        f"Do not weaken this guard to reduce friction. Reach for the sanctioned path, or stop\n"
        f"and ask a human."
    )
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


# ---------------------------------------------------------------------------
# Self-test.
#
# WHY THIS EXISTS, because it will look like over-engineering otherwise:
# a control that inspects the REQUEST cannot be black-box tested from inside the system it
# governs. Every probe is itself a request the control will judge. Try to verify this hook
# by running a test command and the hook denies the test.
#
# The obvious workaround - write the cases to a file and have Bash read them forward - is a
# deliberate bypass of the very control under audit.
#
# So this is the sanctioned path: call decide() DIRECTLY as a library function against cases
# held in a fixture file. No Bash command is ever constructed, so there is nothing for the
# guard to judge and nothing to bypass. The fixture contains no real credentials.
#
#     python3 hooks/token_leak_guard.py --selftest
#
# Exit 0 = every case behaves as declared. Exit 1 = a regression.
#
# GENERAL LESSON, worth more than this hook: design the verification path in at BUILD time
# for any control of this shape. Retrofitting one is expensive and you will be tempted to
# skip it.
# ---------------------------------------------------------------------------
CASES_FILE = "token_leak_guard_cases.json"


def selftest() -> int:
    from pathlib import Path

    path = Path(__file__).with_name(CASES_FILE)
    if not path.exists():
        print(f"selftest: fixture not found at {path}", file=sys.stderr)
        return 1
    cases = json.loads(path.read_text(encoding="utf-8"))["cases"]

    width = max(len(c["note"]) for c in cases)
    failures = []
    for c in cases:
        hit = decide(c["command"])
        got = "block" if hit else "pass"
        label = hit[1] if hit else ""
        ok = got == c["expect"]
        if not ok:
            kind = "FALSE NEGATIVE (leak allowed)" if c["expect"] == "block" else "FALSE POSITIVE (safe blocked)"
            failures.append((c["note"], kind))
        else:
            kind = "ok"
        print(f"{c['note']:<{width}}  want={c['expect']:<5} got={got:<5} {kind}"
              + (f"  [{label}]" if label else ""))

    print("-" * (width + 46))
    print(f"{len(cases) - len(failures)}/{len(cases)} correct")
    for note, kind in failures:
        print(f"  FAIL  {note}: {kind}")
    return 1 if failures else 0


def main() -> None:
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    try:
        data = json.load(sys.stdin)
        if data.get("tool_name", "") != "Bash":
            sys.exit(0)

        cmd = (data.get("tool_input", {}) or {}).get("command", "") or ""
        if not cmd:
            sys.exit(0)

        match = decide(cmd)
        if match:
            _, label = match
            block(cmd, label)

    except json.JSONDecodeError:
        sys.exit(0)
    except Exception as e:
        # Fail open. A guard that breaks your workflow gets uninstalled, and an
        # uninstalled guard protects nothing.
        print(f"token_leak_guard error: {e}", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
