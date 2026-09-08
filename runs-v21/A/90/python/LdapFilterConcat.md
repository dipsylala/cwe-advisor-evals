## Verdict
CONFIRMED. Line 17 concatenates unsanitized user input directly into an LDAP filter string, enabling injection of LDAP metacharacters that alter query logic.

## Source
Line 12: `username = request.args.get("username", "")` provides untrusted input.
Line 17: `search_filter = "(uid=" + username + ")"` concatenates it without escaping.
Line 20: `conn.search(BASE_DN, search_filter, ...)` executes the constructed filter.

## Fix
### File: LdapFilterConcat.py
```python
from flask import Flask, request, jsonify
from ldap3 import Server, Connection, ALL
from ldap3.utils.dn import escape_filter_chars

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
Added `from ldap3.utils.dn import escape_filter_chars` to import ldap3's built-in escaping function. Modified line 20 to `search_filter = "(uid=" + escape_filter_chars(username) + ")"`, which escapes special LDAP metacharacters (`*`, `(`, `)`, `\`, `/`, null) to their literal representations. This prevents an attacker from injecting filter syntax like `uid=*` or `uid=*)(objectClass=*` and closes the injection sink.
