## Verdict

The vulnerability is confirmed. Line 20 calls `conn.search()` with a filter string constructed via string concatenation at line 17, where untrusted user input from `request.args.get("username", "")` is directly interpolated without escaping. An attacker can inject LDAP metacharacters to modify the query structure and bypass authentication or extract sensitive directory data.

## Source

Line 12: `username = request.args.get("username", "")` provides untrusted user input.

Line 17: `search_filter = "(uid=" + username + ")"` concatenates the username directly into the LDAP filter string without escaping.

Line 20: `conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])` passes the unsanitized filter to the LDAP search operation (the taint sink).

## Fix

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

    # Validate input against allowlist pattern (alphanumeric and underscore only)
    if not username or not re.match(r"^[a-zA-Z0-9_]+$", username):
        return jsonify({"error": "invalid username"}), 400

    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, auto_bind=True)

    # Escape username for safe LDAP filter construction
    escaped_username = escape_filter_chars(username)
    search_filter = f"(uid={escaped_username})"

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

The fix uses `escape_filter_chars()` from `ldap3.utils.conv` to neutralize LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) in the username before filter construction. This prevents attackers from injecting syntax to modify the query structure—for example, a payload like `*)(|(uid=*` would be escaped and treated as literal characters rather than operators.

The fix also adds allowlist validation using a regex pattern (`^[a-zA-Z0-9_]+$`) to restrict usernames to safe alphanumeric characters and underscore, reducing the attack surface further. This is defence-in-depth: escaping is the primary control, and the allowlist catches unexpected input patterns early.

Line 25 now safely constructs the filter using `escape_filter_chars()`, ensuring the LDAP server receives a properly structured query with the username treated as data, not query syntax.
