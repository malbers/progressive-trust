#!/usr/bin/env python3
"""authed_call.py - make an authenticated HTTP call without a credential entering a command string.

WHY THIS EXISTS

A widely-taught pattern for keeping tokens out of an AI agent's tool-call payload is
command substitution:

    curl -H "Authorization: Bearer $(cat ~/.secrets/api_token)" https://api.example.com

That advice is half right, and the half it gets wrong is the half that leaks.

What it gets right: the shell expands the substitution locally, so only the literal text
`$(cat ~/.secrets/api_token)` is transmitted in the command. The token itself is not in the
INPUT payload. People who defend this pattern are correct about that.

What it misses: the OUTPUT side. `curl` prints the response. If the endpoint echoes the
token back, redirects with it in a URL, or returns it inside an error body, the value lands
in the transcript anyway. A PreToolUse hook inspects the command, never the output, so it
cannot help. Every real credential leak we have seen came from output, not input.

It also trains a habit that goes wrong on its own: pointing commands at credential files.
The step from `$(cat secret)` to a one-line script that reads and prints the secret is very
short, and that script is what actually leaks.

So this helper takes the secret BY NAME, reads it itself, and masks it in everything it
prints - including HTTP error bodies and redirect URLs. Both sides are covered, and the
guard can stay strict without creating friction that pushes people toward workarounds.

USAGE

    python3 scripts/authed_call.py --secret-name github_token --auth token \
        --url https://api.github.com/user --select login,id

    python3 scripts/authed_call.py --secret-name api_key \
        --method POST --url https://api.example.com/things --data '{"name":"x"}'

    # ordinary (non-secret) query params, repeatable
    python3 scripts/authed_call.py --secret-name github_token --auth token \
        --url https://api.github.com/repos/o/r/issues \
        --query-param state=open --query-param per_page=5

The flag is --secret-name, not --secret, on purpose. `--secret <value>` is itself an
inline-credential shape, and a good PreToolUse guard blocks it.

SECRETS DIRECTORY
Defaults to ~/.secrets. Override with the AUTHED_CALL_SECRETS_DIR environment variable.
One secret per file, bare filename, file contents are the value. Keep the directory out of
every repo and chmod it 700.

VERIFY
    python3 scripts/authed_call.py --selftest

Exercises the URL builder and the masker as library calls against a fake sentinel value.
No real credential is involved.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SECRETS_DIR = Path(os.environ.get("AUTHED_CALL_SECRETS_DIR", Path.home() / ".secrets"))

REDACTED = "***REDACTED***"


def load_secret(name: str) -> str:
    """Read a secret by bare filename. Rejects path traversal; never echoes the value."""
    if "/" in name or "\\" in name or name.startswith("."):
        sys.exit("refusing a path-like --secret-name; pass the bare filename only")
    path = SECRETS_DIR / name
    if not path.is_file():
        # Name the directory and the file, never the contents.
        sys.exit(f"no such secret: {name} (looked in {SECRETS_DIR})")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        sys.exit(f"secret {name} is empty")
    return value


def mask(text: str, secret: str) -> str:
    """Scrub the secret from anything on its way to stdout or stderr.

    This is THE point of the script. A response body, a redirect URL or an error payload can
    echo a credential straight back, and a Bash guard sees the command, never the output.
    Masking has to happen at the print site, which is here.

    quote_plus matters as much as quote: urlencode() uses quote_plus, so a secret carried as
    a query param comes back with spaces as '+', and a mask that only knew %20 would miss
    the exact form this script itself produces.
    """
    if not secret:
        return text
    out = text.replace(secret, REDACTED)
    for variant in (
        secret.strip(),
        urllib.parse.quote(secret, safe=""),
        urllib.parse.quote_plus(secret),
    ):
        if variant and variant != secret:
            out = out.replace(variant, REDACTED)
    return out


def build_url(url: str, params: list, secret: str = None, secret_param: str = None) -> str:
    """Append query params, preserving any the URL already carries.

    Parsed and re-encoded rather than string-concatenated, so a URL that already has a query
    string, or a value containing & or =, cannot silently corrupt the request.
    """
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    for item in params:
        if "=" not in item:
            sys.exit(f"--query-param must be KEY=VALUE, got: {item}")
        key, value = item.split("=", 1)
        query.append((key, value))
    if secret is not None:
        query.append((secret_param, secret))
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(query), parts.fragment)
    )


def select(data, paths):
    """Tiny field extractor, so you do not need jq and do not print an entire API body."""
    def pluck(obj):
        row = {}
        for p in paths:
            cur = obj
            for part in p.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
                if cur is None:
                    break
            row[p] = cur
        return row

    return [pluck(o) for o in data] if isinstance(data, list) else pluck(data)


def selftest() -> int:
    """Exercise build_url + mask as LIBRARY CALLS against a fake sentinel.

    FAKE is not a credential, it is a sentinel chosen to contain a space, a slash and a plus
    so that all three encodings get exercised.
    """
    FAKE = "s3cret val/ue+1"
    cases, failed = [], 0

    def check(name, got, want):
        nonlocal failed
        ok = got == want
        if not ok:
            failed += 1
        cases.append((ok, name, got, want))

    check("plain param",
          build_url("https://x.test/a", ["state=open"]),
          "https://x.test/a?state=open")
    check("repeated params keep order",
          build_url("https://x.test/a", ["b=1", "c=2"]),
          "https://x.test/a?b=1&c=2")
    check("preserves an existing query string",
          build_url("https://x.test/a?keep=yes", ["b=1"]),
          "https://x.test/a?keep=yes&b=1")
    check("value containing & is encoded, not injected",
          build_url("https://x.test/a", ["q=1&admin=true"]),
          "https://x.test/a?q=1%26admin%3Dtrue")
    check("fragment survives",
          build_url("https://x.test/a#frag", ["b=1"]),
          "https://x.test/a?b=1#frag")

    # The half that matters: whatever build_url produced must be scrubbable.
    #
    # ASSERT ON THE ENCODED FORM, NOT THE RAW ONE. An earlier version of this test checked
    # `FAKE in mask(url)` and passed against a deliberately broken mask, because the raw
    # secret is never in an encoded URL to begin with. The assertion was true no matter what
    # mask() did. A negative-control run (delete quote_plus from mask, expect red) is what
    # exposed it. Keep the precondition case below: it is what makes the next one real.
    url = build_url("https://x.test/links", ["v=1"], FAKE, "key")
    encoded = urllib.parse.quote_plus(FAKE)
    check("precondition: the encoded secret IS in the raw url", encoded in url, True)
    check("mask scrubs the url-encoded secret", encoded in mask(url, FAKE), False)
    check("mask scrubs the %20-encoded secret",
          urllib.parse.quote(FAKE, safe="") in mask(urllib.parse.quote(FAKE, safe=""), FAKE), False)
    check("mask scrubs the raw secret", FAKE in mask(f"error at {FAKE}", FAKE), False)
    check("mask leaves non-secret text alone", mask("nothing here", FAKE), "nothing here")

    for ok, name, got, want in cases:
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            print(f"       got:  {got!r}")
            print(f"       want: {want!r}")
    print("-" * 60)
    print(f"{len(cases) - failed}/{len(cases)} correct")
    return 1 if failed else 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--secret-name", help="bare filename inside the secrets directory")
    ap.add_argument("--url")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--auth", default="bearer", choices=["bearer", "token", "basic", "none"],
                    help="Authorization scheme. 'token' is GitHub's form.")
    ap.add_argument("--header", action="append", default=[], help="extra header, 'K: V'")
    ap.add_argument("--query-param", action="append", default=[], help="KEY=VALUE, repeatable")
    ap.add_argument("--secret-in", default="header", choices=["header", "query"],
                    help="where the credential travels. Prefer header.")
    ap.add_argument("--secret-param", default="key", help="query param name when --secret-in query")
    ap.add_argument("--data", help="request body; @file.json reads from a file")
    ap.add_argument("--select", help="comma-separated dotted field paths to print")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if not args.secret_name or not args.url:
        ap.error("--secret-name and --url are required")

    secret = load_secret(args.secret_name)

    # --secret-in query is a WEAKER posture than a header, and is offered only because some
    # APIs give no choice. URLs land in server logs, proxy logs and Referer headers in a way
    # Authorization headers do not. The masking here covers the local side, which is the
    # half this script owns. It can do nothing about the remote side.
    if args.secret_in == "query":
        url = build_url(args.url, args.query_param, secret, args.secret_param)
        headers = {}
    else:
        url = build_url(args.url, args.query_param)
        scheme = {"bearer": "Bearer", "token": "token", "basic": "Basic"}.get(args.auth)
        headers = {} if args.auth == "none" else {"Authorization": f"{scheme} {secret}"}

    for h in args.header:
        if ":" not in h:
            sys.exit(f"--header must be 'K: V', got: {h}")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()

    body = None
    if args.data:
        raw = Path(args.data[1:]).read_text(encoding="utf-8") if args.data.startswith("@") else args.data
        body = raw.encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    headers.setdefault("User-Agent", "authed-call/1.0")

    req = urllib.request.Request(url, data=body, headers=headers, method=args.method.upper())
    try:
        with urllib.request.urlopen(req) as resp:
            text = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        # The error body is exactly where a credential gets echoed back. Mask before print.
        detail = e.read().decode("utf-8", "replace")
        print(mask(f"HTTP {e.code} {e.reason}\n{detail}", secret), file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(mask(f"connection failed: {e.reason}", secret), file=sys.stderr)
        sys.exit(1)

    if args.select:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            print(mask(text, secret))
            return
        out = select(parsed, [p.strip() for p in args.select.split(",")])
        print(mask(json.dumps(out, indent=2), secret))
    else:
        print(mask(text, secret))


if __name__ == "__main__":
    main()
