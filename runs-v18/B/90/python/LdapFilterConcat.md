## Verdict

CONFIRMED: CWE-90 LDAP Injection vulnerability at line 20. User-controlled input `username` is concatenated directly into the LDAP filter string without escaping, allowing attackers to inject LDAP syntax and manipulate the query.

## Source

The vulnerability originates at line 12:
```python
username = request.args.get("username", "")
```

The `username` parameter is untrusted HTTP input from `request.args`. This value flows directly into the LDAP filter construction at line 17 via string concatenation:
```python
search_filter = "(uid=" + username + ")"
```

The `search_filter` is then passed to the taint sink at line 20:
```python
conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
```

An attacker can inject LDAP filter syntax (e.g., `*`, `(`, `)`) to modify the query logic, bypass filters, or extract additional data.

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

    escaped_username = escape_filter_chars(username)
    search_filter = f"(uid={escaped_username})"

    # Fixed: User input is now escaped using ldap3's escape_filter_chars()
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

The fix applies RFC 4515 escaping to the user-controlled `username` value before constructing the LDAP filter string. By using `ldap3.utils.conv.escape_filter_chars()`, all special LDAP filter characters (`*`, `(`, `)`, `\`, NUL) are neutralized. This prevents an attacker from injecting filter syntax.

The import statement `from ldap3.utils.conv import escape_filter_chars` is added to access the escaping function. The username is escaped and assigned to `escaped_username` at line 21, and the f-string on line 22 constructs the filter with the escaped value. This separates query structure from user data, closing the injection point.

The fix preserves the original function's contract: it returns search results in `conn.entries`, the unbind and return logic remain unchanged, and the error handling is unaffected. The only behavioral change is the input escaping, which neutralizes special characters but preserves the legitimate value for matching.

## Behaviour changes

- **Before**: A request like `GET /directory/lookup?username=*` would escape filter syntax and match all users in the LDAP directory. A payload like `admin*` would bypass partial matching constraints.
- **After**: The same requests are now safe. `escape_filter_chars('*')` produces `\2a` (escaped form), and the filter becomes `(uid=\2a)`, which searches for a literal asterisk character in the `uid` attribute rather than a wildcard. Legitimate usernames with special characters are similarly escaped and remain searchable.

The application's functional behavior is preserved: valid usernames are still found, invalid usernames still return a 404, and the returned entries contain the expected attributes. The only difference is that LDAP injection is no longer possible.
