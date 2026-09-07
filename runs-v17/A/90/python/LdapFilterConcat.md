## Verdict
Confirmed. The `username` parameter is concatenated directly into the LDAP filter string without escaping, allowing an attacker to inject LDAP metacharacters and manipulate the query logic.

## Source
Line 17-20 in `LdapFilterConcat.py`:
```python
search_filter = "(uid=" + username + ")"
conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
```

The `username` value originates from untrusted user input (`request.args.get("username")`) and is concatenated directly into the LDAP filter passed to `conn.search()`.

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

    search_filter = "(uid=" + escape_filter_chars(username) + ")"

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

## Explanation
The fix uses `escape_filter_chars()` from `ldap3.utils.conv` to properly escape the user-supplied `username` before inserting it into the LDAP filter. This function escapes LDAP filter metacharacters (`*`, `(`, `)`, `\`, and null bytes) by converting them to their escaped hex representations (e.g., `*` becomes `\2a`), preventing filter injection attacks.

For example, an attacker input like `*)(|(uid=*` is escaped to `\2a\29\28\7c\28uid\3d\2a`, making it a literal string within the filter rather than filter syntax. This preserves the intended query logic while neutralizing the malicious payload.
