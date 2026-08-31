## Verdict

Confirmed LDAP injection vulnerability. The username parameter from the HTTP request is directly concatenated into an LDAP filter string without escaping, allowing an attacker to inject LDAP metacharacters and modify the query logic.

## Source

File: LdapFilterConcat.py, line 12
```python
username = request.args.get("username", "")
```

The `username` is untrusted user input from an HTTP GET parameter.

## Fix

Replace the direct string concatenation at line 17 with escaped filter construction. Import `escape_filter_chars` and apply it to the username before building the filter:

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

    # Escape the username before inserting it into the filter
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

The fix escapes the username using `ldap3.utils.conv.escape_filter_chars()` before interpolating it into the LDAP filter string. This function encodes all LDAP filter metacharacters (RFC 4515): `*`, `(`, `)`, `\`, and NUL. When escaped, these characters become literal values within the filter expression rather than syntax operators, preventing the attacker from injecting filter logic. For example, a username `admin*)` becomes the literal string `admin\2a\29` in the filter `(uid=admin\2a\29)`, which searches for a uid value that literally equals `admin*)` rather than allowing the injection to close the clause and open a new one.

## Behaviour changes

The fixed code properly handles usernames containing special characters:
- Input `admin*` (an attacker attempting wildcard injection) → searches for uid literally equal to `admin*` instead of matching `admin`, `admina`, `adminb`, etc.
- Input `ad*min*` → searches for literal value `ad*min*` instead of interpreting `*` as a wildcard
- Input `user*)((uid=*` (complex injection attempt) → searches for literal value containing those characters

Legitimate usernames with special characters (if any exist in the directory) will be correctly handled by the escaped filter. Non-ASCII characters and valid usernames are unaffected.
