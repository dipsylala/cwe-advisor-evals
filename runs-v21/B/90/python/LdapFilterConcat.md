## Verdict

Exploitable.

## Source

Line 12: `username = request.args.get("username", "")` — untrusted HTTP request parameter.

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

The vulnerability occurs because the `username` parameter from the HTTP request is concatenated directly into the LDAP filter string without escaping. An attacker can inject LDAP filter syntax by supplying a username like `*)(uid=*))(&(uid=` to break out of the uid filter and inject arbitrary query logic. The fix applies `escape_filter_chars()` from ldap3's built-in utilities to escape all special LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) in the username before it is used in the filter. This ensures the username is treated as literal data, not LDAP syntax, while preserving the original search functionality. The escaping is applied at the point where the filter is constructed, preventing the injection at the source of the data flow.

## Behaviour changes

The only behaviour change is that LDAP metacharacters in a username (such as `*`, `(`, `)`, `\`) are now escaped and treated as literal characters in the uid filter rather than as LDAP syntax operators. This is the correct and intended behavior: a username containing these characters should be searched for literally, not interpreted as filter syntax. The application would never intentionally search for a wildcard `*` as a literal uid, so this change does not break legitimate functionality. The search scope and result attributes remain unchanged; only the filter construction is made safe.
