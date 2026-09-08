## Verdict

Confirmed. `username` comes from an unauthenticated Flask query parameter (`request.args.get("username", "")`) and is concatenated directly into the LDAP search filter string passed to `conn.search()`. An attacker can inject LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) to alter the filter's logic - for example supplying `*)(uid=*))(|(uid=*` to broaden the match, or `*` alone to enumerate/return arbitrary directory entries - resulting in authentication bypass or unauthorized information disclosure from the directory.

## Source

`request.args.get("username", "")` at line 12, flowing unmodified into the string concatenation at line 17 and then into the `conn.search()` sink at line 20.

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

The root cause is building an LDAP search filter by string concatenation with untrusted input, which lets filter metacharacters change the query's structure (the LDAP equivalent of SQL injection). The fix keeps the same query shape and library call but neutralizes the value before it enters the filter: `ldap3.utils.conv.escape_filter_chars()` applies the RFC 4515 escaping rules, converting `*`, `(`, `)`, `\`, and NUL into their `\XX` hex-escaped forms so they are treated as literal characters to match rather than filter syntax. This is applied only to the untrusted `username` value, not to the surrounding filter template, so a legitimate uid such as `jane.doe` is unaffected while `*)(uid=*` is escaped into a literal string that matches no real uid. No other behavior changes: the search base, attributes requested, and response shape are unchanged.
