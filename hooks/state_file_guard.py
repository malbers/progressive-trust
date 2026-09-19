#!/usr/bin/env python3
"""state_file_guard.py - PreToolUse hook. Blocks whole-file writes to state files.

WHAT THIS PROTECTS
Your memory layer is a set of plain files: an audit log, MEMORY.md, current.md, CLAUDE.md,
a trust config, anything under memory/. They are append-heavy and irreplaceable. An Edit
changes a few lines. A Write replaces the entire file, and everything not in the new
version is gone with no error and no warning.

That distinction is invisible to an agent under time pressure, and the failure is silent,
so nobody goes looking for it. This hook makes it structural: on these files, Edit is the
only way in.

THE THREE VECTORS, and why all three are here
Each was added after the previous one was bypassed. Leaving any out leaves the guard
looking complete while being trivially routed around.

  1. The Write tool. An agent asked to append to an audit log reported "file did not exist,
     created fresh". The file did exist. A single Write replaced months of history with a
     twelve-line stub.

  2. Shell-level writes. Agents blocked on Write fell back to the Bash tool and used shell
     redirection and PowerShell Set-Content instead, bypassing the guard entirely. Covered
     here: > and >> redirection, Set-Content / Add-Content / Out-File / New-Item, tee,
     sed -i, cp/mv/copy/move destinations, dd of=.
     `touch` is deliberately ALLOWED: it is the sanctioned creation path (touch, then Edit).

  3. Inline interpreters. A `python -c "...open(p,'w')..."` rewrite of a protected file
     passed vectors 1 and 2 clean. A scanner that reads shell VERBS cannot see a write
     performed inside an interpreter payload.

     Read-only inline interpreters are still allowed on purpose. A payload must reference a
     protected path AND carry a write primitive to be denied. Blocking
     `python3 -c "print(open(p).read())"` would push work toward workarounds, and a control
     that causes workarounds causes the incident it exists to prevent.

STILL NOT AIRTIGHT, stated honestly rather than disclaimed and forgotten
A payload that builds a protected path from pieces ('cur' + 'rent.md'), reads the path from
a file or argv, or arrives through a channel this hook cannot inspect will pass. Those are
evasion shapes, not ergonomics. The remedy for friction is Edit, which is faster than
writing a script anyway.

Do not disclaim a hole and leave it. In this hook's own history, vector 3 sat documented as
"not airtight" for 82 days before it was used.

INSTALL
Register as a PreToolUse hook matching both Write and Bash:

    {
      "hooks": {
        "PreToolUse": [{
          "matcher": "Write|Edit|Bash",
          "hooks": [{"type": "command", "command": "python3 /abs/path/hooks/state_file_guard.py"}]
        }]
      }
    }

VERIFY
    python3 hooks/state_file_guard.py --selftest

CUSTOMISE
Edit PROTECTED_BASENAMES / PROTECTED_BASENAME_PATTERNS below to match your own file names.
Add a carve-out to is_protected_path() for any same-named file that is genuinely runtime
scratch rather than session state.
"""

import json
import re
import sys
from pathlib import PurePosixPath

# --- What counts as a state file --------------------------------------------
# Adjust these to your own layout. Matching is case-insensitive on the basename.

PROTECTED_BASENAMES = {
    "current.md",
    "shared-current.md",
    "claude.md",
    "trust-config.md",
    "context-index.md",
}

PROTECTED_BASENAME_PATTERNS = [
    # MEMORY.md, MEMORY-projects.md, MEMORY-reference.md, MEMORY-practices.md ...
    (re.compile(r"^memory(-[a-z0-9_-]+)?\.md$"), "MEMORY*.md pattern"),
    # audit-log.md, audit-log-combined.md, laptop-audit-log.md, frozen archives ...
    (re.compile(r"^([a-z0-9_-]+-)?audit-log(-[a-z0-9_-]+)?\.md$"), "audit-log*.md pattern"),
]

# Paths that LOOK protected but are runtime scratch, not session state. Keep this list
# short and specific, and write down why each one is here.
CARVE_OUTS = (
    # a bot's own runtime log, managed by the bot, not session memory
    "todo-bot/audit-log.md",
)


def is_protected_path(raw_path):
    """Return (is_protected, reason) for a single path string."""
    norm = raw_path.replace("\\", "/").strip("'\"` ")
    if not norm:
        return False, ""
    norm_lower = norm.lower()
    basename = PurePosixPath(norm).name
    basename_lower = basename.lower()

    for carve in CARVE_OUTS:
        if carve in norm_lower:
            return False, ""

    if basename_lower in PROTECTED_BASENAMES:
        return True, f"basename '{basename}' is in the protected list"
    for pat, label in PROTECTED_BASENAME_PATTERNS:
        if pat.match(basename_lower):
            return True, f"basename '{basename}' matches {label}"
    # Any *.md under a memory/ directory, regardless of project
    if basename_lower.endswith(".md"):
        parts = [p.lower() for p in PurePosixPath(norm).parts]
        if "memory" in parts:
            return True, "file lives under a memory/ directory"
    return False, ""


def is_protected_write_dest(raw_path):
    """Like is_protected_path, but also treats a memory/ directory itself as a protected
    destination, since `cp x.md memory/` creates a file inside it."""
    hit, reason = is_protected_path(raw_path)
    if hit:
        return hit, reason
    norm_lower = raw_path.replace("\\", "/").strip("'\"` ").lower().rstrip("/")
    if norm_lower == "memory" or norm_lower.endswith("/memory"):
        return True, "destination is a memory/ directory"
    return False, ""


# --- Vector 2: shell command scanning ----------------------------------------

PS_WRITE_CMDLETS = {"set-content", "add-content", "out-file", "new-item"}
PS_PATH_FLAGS = {"-path", "-filepath", "-literalpath", "-destination"}
PS_VALUE_FLAGS = {"-value", "-encoding", "-itemtype"}  # flag + value, value is not a path
COPY_MOVE_CMDS = {"cp", "mv", "copy", "move", "copy-item", "move-item"}
# `>` / `>>` redirection; the lookbehind skips `2>&1`-style fd-to-fd and `<>`
REDIRECT_RE = re.compile(r"(?<![<>&])>{1,2}\s*([^\s|;&<>]+)")
DD_OF_RE = re.compile(r"\bof=([^\s|;&]+)", re.I)


def tokenize(clause):
    return re.findall(r'"[^"]*"|\'[^\']*\'|\S+', clause)


def scan_bash_command(command):
    """Return [(target, reason)] for protected write targets found in a shell command."""
    violations = []

    def check(target, via):
        hit, reason = is_protected_write_dest(target)
        if hit:
            violations.append((target.strip("'\"` "), f"{via} - {reason}"))

    for m in REDIRECT_RE.finditer(command):
        check(m.group(1), "redirection target")
    for m in DD_OF_RE.finditer(command):
        check(m.group(1), "dd of= target")

    # Clause by clause for command-style writers.
    # Do NOT split on `|`: tee and Set-Content sit downstream of pipes.
    clauses = re.split(r"[;\n]|&&|\|\|", command)
    for clause in clauses:
        tokens = tokenize(clause)
        lowered = [t.lower().strip("'\"") for t in tokens]

        for i, tok in enumerate(lowered):
            if tok in PS_WRITE_CMDLETS:
                j = i + 1
                while j < len(tokens):
                    t = lowered[j]
                    if t in PS_VALUE_FLAGS:
                        j += 2
                        continue
                    if t.startswith("-") and t not in PS_PATH_FLAGS:
                        j += 1
                        continue
                    if t in PS_PATH_FLAGS:
                        j += 1
                        continue
                    check(tokens[j], f"{tok} argument")
                    j += 1
            elif tok == "sed" and any(
                t.startswith("-i") or t == "--in-place" for t in lowered[i + 1:]
            ):
                for t in tokens[i + 1:]:
                    if not t.lstrip("'\"").startswith("-"):
                        check(t, "sed -i target")
            elif tok in COPY_MOVE_CMDS:
                args = tokens[i + 1:]
                largs = lowered[i + 1:]
                dest = None
                for k, t in enumerate(largs):
                    if t == "-destination" and k + 1 < len(args):
                        dest = args[k + 1]
                if dest is None:
                    positional = [args[k] for k, t in enumerate(largs) if not t.startswith("-")]
                    if positional:
                        dest = positional[-1]
                if dest:
                    check(dest, f"{tok} destination")
            elif tok == "tee":
                for t in tokens[i + 1:]:
                    if not t.lstrip("'\"").startswith("-"):
                        check(t, "tee target")

    return violations


# --- Vector 3: inline-interpreter scanning -----------------------------------

INTERPRETER_RE = re.compile(
    r"\b(?:py|python[\d.]*|node|nodejs|ruby|perl|pwsh|powershell(?:\.exe)?|deno|bun|osascript)\b",
    re.I,
)
INLINE_FLAG_RE = re.compile(
    r"(?:^|\s)-(?:c|e|E|command|Command|EncodedCommand|encodedcommand|pi|ne|p)\b|<<-?\s*['\"]?\w+",
)
ENCODED_CMD_RE = re.compile(r"-encodedcommand\s+([A-Za-z0-9+/=]+)", re.I)

# Write primitives, by language. Read-only payloads are deliberately not matched.
WRITE_INDICATOR_RE = re.compile(
    r"""(?xi)
    open\s*\([^)]*['"][wax]\+?['"]          # python/ruby: open(p, 'w'|'a'|'x')
  | \.\s*write(?:lines|_text|_bytes)?\s*\(
  | \btruncate\s*\(
  | \bjson\s*\.\s*dump\s*\(
  | \bshutil\s*\.\s*(?:copy\w*|move)\s*\(
  | \bos\s*\.\s*(?:replace|rename|remove|unlink)\s*\(
  | \bpathlib\b[^\n]*\bwrite
  | \bwrite_?file(?:_?sync)?\s*\(           # node
  | \bappend_?file(?:_?sync)?\s*\(
  | \bcreate_?write_?stream\s*\(
  | \bFile\s*\.\s*(?:write|open|delete)\b   # ruby / perl
  | \bunlink\s*\(
  | \b(?:set|add)-content\b | \bout-file\b | \bremove-item\b
    """
)


def _decode_powershell_encoded(command):
    """PowerShell -EncodedCommand is base64 UTF-16LE. Decode it so the payload is
    inspectable. An unreadable payload must not be a free pass."""
    out = []
    for m in ENCODED_CMD_RE.finditer(command):
        blob = m.group(1)
        for enc in ("utf-16-le", "utf-8"):
            try:
                import base64
                out.append(base64.b64decode(blob + "=" * (-len(blob) % 4)).decode(enc, "ignore"))
                break
            except Exception:
                continue
    return out


def _candidate_paths(text):
    """Every quoted literal, plus bare tokens that look like a path or .md file."""
    cands = re.findall(r'"([^"\n]*)"|\'([^\'\n]*)\'', text)
    flat = [a or b for a, b in cands]
    flat += re.findall(r"[\w./\\-]*\.md\b", text)
    flat += re.findall(r"[\w./\\-]*/memory/?", text)
    return [c for c in flat if c]


def scan_inline_interpreter(command):
    """Return [(target, reason)] where an inline payload BOTH names a protected file AND
    carries a write primitive."""
    if not INTERPRETER_RE.search(command) or not INLINE_FLAG_RE.search(command):
        return []

    payloads = [command] + _decode_powershell_encoded(command)
    violations = []
    seen = set()
    for payload in payloads:
        if not WRITE_INDICATOR_RE.search(payload):
            continue
        for cand in _candidate_paths(payload):
            hit, reason = is_protected_write_dest(cand)
            if hit:
                key = cand.strip("'\"` ")
                if key not in seen:
                    seen.add(key)
                    violations.append((key, f"inline interpreter write - {reason}"))
    return violations


# --- Decision ----------------------------------------------------------------


def _deny_payload(reason):
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def decide(tool_name, tool_input):
    """THE single decision function. The live hook and --selftest both call THIS.

    Why that matters: a sibling guard's first selftest ran a different code path than
    production and confidently reported a false positive production did not have. A
    selftest on a different path than the control is worse than none. Keep the
    single-entry-point shape if you adapt this.

    Returns (decision, reason) where decision is 'allow' or 'deny'.
    """
    tool_input = tool_input or {}

    if tool_name == "Write":
        raw_path = tool_input.get("file_path", "") or ""
        is_protected, match_reason = is_protected_path(raw_path)
        if is_protected:
            return "deny", (
                f"STATE FILE GUARD: blocked Write on '{raw_path}'.\n\n"
                f"Match: {match_reason}.\n\n"
                "State files (audit log, MEMORY*, current.md, CLAUDE.md, trust-config, "
                "memory/*.md) must not be written with the Write tool. A Write replaces the "
                "whole file and anything not in the new version is gone, silently.\n\n"
                "Use Edit.\n\n"
                "Creating a NEW state file: `touch <path>` first (allowed), then Edit. That "
                "forces explicit creation rather than implicit overwrite.\n\n"
                "Appending: read the file, use its last line as an anchor, and Edit "
                "last_line -> last_line + new_content.\n\n"
                "If Read fails for any reason - wrong path, permission, anything - STOP and "
                "escalate. Do NOT fall back to Write."
            )

    elif tool_name == "Bash":
        command = tool_input.get("command", "") or ""

        violations = scan_bash_command(command)
        if violations:
            listing = "\n".join(f"  - '{t}' ({v})" for t, v in violations)
            return "deny", (
                "STATE FILE GUARD: blocked Bash command - it writes to protected state "
                f"file(s):\n{listing}\n\n"
                "Shell-level writes (>, >>, tee, sed -i, cp/mv, Set-Content, Out-File) to "
                "state files are banned the same as the Write tool.\n\n"
                "Use Edit. Do NOT route around this with another shell primitive: that exact "
                "move is why this check exists.\n\n"
                "Creating a NEW state file: `touch <path>` (allowed), then Edit.\n"
                "Archiving or deleting within memory/: stop and ask a human first."
            )

        inline = scan_inline_interpreter(command)
        if inline:
            listing = "\n".join(f"  - '{t}' ({v})" for t, v in inline)
            return "deny", (
                "STATE FILE GUARD: blocked Bash command - an INLINE INTERPRETER payload "
                f"writes to protected state file(s):\n{listing}\n\n"
                "A write inside `python -c` / `node -e` / a heredoc / `pwsh -EncodedCommand` "
                "is the same act as Write or `>`, and is banned the same way.\n\n"
                "THE SANCTIONED PATH, because friction is what causes incidents: read the "
                "file, anchor on its last line, Edit last_line -> last_line + new_content. "
                "That is faster than writing a script, not slower.\n\n"
                "Reading is fine. This fired only because the payload carries a write "
                "primitive AND names a protected path.\n\n"
                "Do NOT rephrase, split or obfuscate the path to get past this matcher. That "
                "is evasion, not a fix."
            )

    return "allow", ""


# --- Selftest ----------------------------------------------------------------


def run_selftest():
    """Exercise decide() as a LIBRARY CALL. No Bash command is constructed, so there is
    nothing to bypass, and no real state file is touched."""
    from pathlib import Path

    fixture = Path(__file__).with_name("state_file_guard_cases.json")
    try:
        cases = json.loads(fixture.read_text(encoding="utf-8"))["cases"]
    except Exception as exc:
        print(f"SELFTEST ERROR: cannot read {fixture.name}: {exc}")
        return 1

    failures = []
    for case in cases:
        got, _ = decide(case["tool_name"], case["tool_input"])
        status = "ok" if got == case["expect"] else "FAIL"
        if status == "FAIL":
            failures.append(f"  [{case['id']}] {case['why']}\n      expected {case['expect']}, got {got}")
        print(f"  {case['id']:<34} want={case['expect']:<5} got={got:<5} {status}")

    total = len(cases)
    print("-" * 66)
    if failures:
        print(f"SELFTEST: {total - len(failures)}/{total} passed, {len(failures)} FAILED")
        print("\n".join(failures))
        return 1
    print(f"SELFTEST: {total}/{total} passed. No real state files were touched.")
    return 0


# --- Main --------------------------------------------------------------------

if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(run_selftest())

    try:
        data = json.load(sys.stdin)
        decision, reason = decide(data.get("tool_name", ""), data.get("tool_input", {}))
        if decision == "deny":
            print(json.dumps(_deny_payload(reason)))
    except Exception as exc:
        # Fail open. A guard that breaks your workflow gets uninstalled.
        print(f"state_file_guard error: {exc}", file=sys.stderr)
    sys.exit(0)
