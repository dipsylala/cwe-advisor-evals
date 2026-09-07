## Verdict

Exploitable. Untrusted user input from `request.args.get("username")` is concatenated directly into an LDAP filter string without escaping or validation, allowing an attacker to inject LDAP filter metacharacters (e.g., `*`, `(`, `)`) to modify query logic, bypass authentication, or extract unauthorized directory data.

## Source

Line 12: `username = request.args.get("username", "")` — untrusted HTTP request parameter.

## Sink

Line 20: `conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])` — LDAP search execution with user-controlled filter string.

## Data Flow

1. Untrusted `username` parameter captured from HTTP request (line 12)
2. Concatenated directly into filter string without escaping (line 17: `"(uid=" + username + ")"`)
3. Filter passed to `conn.search()` which parses and executes it against the LDAP directory (line 20)

An attacker can inject LDAP syntax: e.g., username `*` returns all users; `admin*))(|(uid=*` can bypass authentication logic.

## Fix

### File: LdapFilterConcat.py

```python
from flask import Flask, request, jsonify
from ldap3 import Server, Connection, ALL
from ldap3.utils.conv import escape_filter_chars
import re

app = Flask(__name__)

LDAP_SERVER = "ldap://directory.internal:389"
BASE_DN = "ou=users,dc=example,dc=com"


@app.route("/directory/lookup")
def lookup_user():
    username = request.args.get("username", "")

    # Validate username against allowlist (alphanumeric and dots/hyphens only)
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        return jsonify({"error": "invalid username format"}), 400

    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, auto_bind=True)

    # Escape special LDAP characters in the username value
    escaped_username = escape_filter_chars(username)
    search_filter = "(uid=" + escaped_username + ")"

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

The fix applies two layers of defence:

1. **Allowlist validation** (line 19-20): A regex pattern restricts usernames to alphanumeric characters, dots, and hyphens—the format typical for LDAP usernames. This rejects injection attempts with special characters (`*`, `(`, `)`, etc.) at the point of entry. Rejected requests return a 400 error to the caller.

2. **LDAP filter escaping** (line 25): The `escape_filter_chars()` function from `ldap3.utils.conv` escapes all special LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) in the validated username before building the filter string. This protects against injection patterns that may evade the allowlist or arrive from other sources in future refactoring.

Together, these controls prevent untrusted data from modifying LDAP query structure. The allowlist stops most injection attempts before escaping; the escaping provides a secondary defence layer ensuring the username is treated as a literal value, not filter syntax.

## Behaviour changes

1. **Input validation added**: Requests with invalid username formats now return HTTP 400 instead of executing the query. This is a security-necessary change—invalid usernames would fail the LDAP query anyway, so rejecting them early is consistent with expected behaviour.

2. **Import additions**: Added `from ldap3.utils.conv import escape_filter_chars` and `import re` to support escaping and validation. These are standard library and ldap3's own utilities (already a dependency).

3. **No change to search result contract**: The search still uses the same `BASE_DN`, attributes list, and entry processing. Return values, error handling, and data structure remain identical for valid inputs.

## Verification

Python syntax check: passed via `python -m py_compile`.

Dependencies verified:
- `escape_filter_chars()` — from `ldap3.utils.conv`, documented in ldap3 library
- `re.match()` — Python standard library module
- `jsonify()`, `request`, `Flask` — already imported in original code

All names and imports are valid and reachable.
