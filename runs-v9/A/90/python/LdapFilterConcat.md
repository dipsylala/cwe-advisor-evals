## Verdict
Confirmed. The `username` query parameter is concatenated directly into an LDAP search filter string, allowing LDAP filter injection.

## Source
`username = request.args.get("username", "")` (line 12) - attacker-controlled HTTP query parameter, passed unvalidated and unescaped into the filter built on line 17 and used at the search sink on line 20 (`conn.search(BASE_DN, search_filter, ...)`).

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
`ldap3.utils.conv.escape_filter_chars` applies the RFC 4515 escaping rules for LDAP search filters: it converts the special characters `*`, `(`, `)`, `\`, and NUL (and, depending on the ldap3 version, non-ASCII bytes) into their `\XX` hex-escaped form before the value is embedded in the filter string. This neutralizes the two classic LDAP injection primitives:

- **Filter logic manipulation** - an attacker submitting `username=*)(uid=*))(|(uid=*` (or similar) can no longer close the `(uid=...)` clause early and splice in additional filter terms such as `(objectClass=*)` or an always-true `(|...)` branch, because the `(`, `)`, and `*` characters in the input are escaped rather than interpreted as filter syntax.
- **Blind LDAP injection / attribute enumeration** - wildcard characters (`*`) in the username can no longer be used to turn an exact `uid` match into a substring search that leaks whether other attributes match, since `*` is escaped to a literal value rather than acting as a wildcard.

The fix is applied at the point where the untrusted value is interpolated into the filter (line 17 equivalent), not at the sink, so `search_filter` reaching `conn.search()` is always a syntactically well-formed filter with the user-supplied value treated strictly as data. This preserves the intended lookup-by-uid behavior for legitimate usernames while eliminating the ability to alter the filter's structure. Structured/parameterized filter builders are not part of ldap3's API, so escaping the untrusted component before string concatenation is the correct and idiomatic mitigation for this library.
