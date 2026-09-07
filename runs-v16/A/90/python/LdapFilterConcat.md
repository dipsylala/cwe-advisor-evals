## Verdict

The LDAP injection vulnerability is real. Line 17 constructs an LDAP filter by directly concatenating user input without escaping special LDAP characters. An attacker can inject LDAP metacharacters (such as `*`, `(`, `)`, `&`, `|`) to modify the filter logic and bypass authentication or retrieve unauthorized data.

## Source

```python
from flask import Flask, request, jsonify
from ldap3 import Server, Connection, ALL

app = Flask(__name__)

LDAP_SERVER = "ldap://directory.internal:389"
BASE_DN = "ou=users,dc=example,dc=com"


@app.route("/directory/lookup")
def lookup_user():
    username = request.args.get("username", "")

    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, auto_bind=True)

    search_filter = "(uid=" + username + ")"

    # SAST FINDING: CWE-90 (Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')) reported here. Sink is the next statement.
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

The vulnerability occurs because the `username` parameter from the HTTP request is concatenated directly into the LDAP search filter without any sanitization. LDAP filter syntax treats characters like `*`, `(`, `)`, `&`, `|`, and `\` as metacharacters that control filter logic. An attacker can inject these characters to craft arbitrary filters.

For example, with username `*)(uid=*))(|(uid=*`, the resulting filter becomes `(uid=*)(uid=*))(|(uid=*)`, which matches any user.

The fix imports `escape_filter_chars` from `ldap3.utils.conv` and uses it to escape the user input before incorporating it into the filter. This function replaces special LDAP characters with their escaped equivalents, rendering them literals rather than operators. After escaping, the untrusted input is safe to use in LDAP filter construction.

The ldap3 library's escape function is the standard way to neutralize LDAP injection in Python when building filters dynamically.
