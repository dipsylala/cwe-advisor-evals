## Verdict
Confirmed. `search_filter` is built by directly concatenating the untrusted `username` request parameter into an LDAP filter string, allowing LDAP filter injection (CWE-90).

## Source
`username = request.args.get("username", "")` (line 12) - attacker-controlled HTTP query parameter, flows unsanitized into the filter built on line 17 and passed to `conn.search()` on line 20.

## Fix
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
`escape_filter_chars` (from `ldap3.utils.conv`) applies the RFC 4515 escaping rules for LDAP search filters, converting each of the special characters `*`, `(`, `)`, `\`, and NUL into its `\XX` hex-escaped form before the value is embedded in the filter string. This neutralizes the two classic LDAP injection primitives: wildcard/filter-logic manipulation (e.g. `*` turning `(uid=*)` into a match-everything query, or `)(|(uid=*` injecting extra filter clauses to bypass intended scope) and premature filter termination via unescaped parentheses. Escaping is applied at the point the untrusted value is incorporated into the filter, immediately before concatenation, so every code path building `search_filter` from `username` is covered. The rest of the data flow (connection setup, search invocation, result handling) is unchanged - only the value placed into the filter is different, which keeps the fix minimal and behavior-preserving for legitimate usernames (alphanumeric input round-trips unmodified through the escape function).
