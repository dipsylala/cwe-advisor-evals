## Verdict

Exploitable. CWE-90 (LDAP Injection), confidence: high.

## Source

`username = request.args.get("username", "")` (line 12) - an unauthenticated, attacker-controlled HTTP query parameter with no validation or escaping applied anywhere in the function.

## Fix

### File: LdapFilterConcat.py

```python
from flask import Flask, request, jsonify
from ldap3 import Server, Connection, ALL
from ldap3.utils.conv import escape_filter_chars

app = Flask(__name__)

LDAP_SERVER = "ldap://directory.internal:389"
BASE_DN = "ou=users,dc=example,dc=com"


@app.route("/directory/lookup")
def lookup_user():
    username = request.args.get("username", "")

    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, auto_bind=True)

    safe_username = escape_filter_chars(username)
    search_filter = "(uid=" + safe_username + ")"

    conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])

    entries = conn.entries
    conn.unbind()

    if not entries:
        return jsonify({"error": "user not found"}), 404

    entry = entries[0]
    return jsonify({
        "cn": str(entry.cn),
        "mail": str(entry.mail),
        "uid": str(entry.uid),
    })


if __name__ == "__main__":
    app.run()
```

## Explanation

The handler built the LDAP search filter by concatenating the raw `username` query parameter directly into `"(uid=" + username + ")"`, so any RFC 4515 metacharacter the caller supplied (`*`, `(`, `)`, backslash) became live filter syntax rather than data - a bare `*` turns the equality test into a match-everything wildcard, and `)(` sequences can close the intended term and open another. The fix escapes `username` with `ldap3.utils.conv.escape_filter_chars()` before it is concatenated into the filter string, which converts every RFC 4515-significant character (`*`, `(`, `)`, `\`, NUL) into its `\XX` hex escape. The escaped value can no longer alter the filter's structure, so it is always evaluated as a literal `uid` comparison regardless of what the caller sends. No application-defined format constraint exists for `username` in this code, so no additional allowlist was added per the guidance's caution against allowlists chosen for security alone.

## Behaviour changes

- Added import `from ldap3.utils.conv import escape_filter_chars` - required by the fix; `ldap3.utils.conv.escape_filter_chars` is the escaping function named explicitly in the loaded `cwe/90/python/INDEX.md` guidance and taint-sink entry.
- `search_filter` is now built from `safe_username` (the escaped value) instead of the raw `username` - this is the injection fix itself.
- For a `username` value containing no LDAP filter metacharacters, `escape_filter_chars()` returns the string unchanged, so the search filter, the `conn.search()` call (arguments, base DN, attribute list), the returned `entries`, and the JSON response shape are all identical to the original for legitimate input. No other behaviour changed.

**Verification**: `python -m py_compile` (CPython 3.13.12) on the fixed file in a scratch copy - passed with no syntax errors. `escape_filter_chars` was not further verified against an installed `ldap3` package (none was available in the environment); it is used here because it is the exact name the loaded language-specific guidance's Key Principles and Taint Sinks sections give as the primary defence and correct import path (`ldap3.utils.conv`), so it is not treated as an unverified name under the Step 5 existence check.
