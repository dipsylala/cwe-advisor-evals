## Verdict

Exploitable. The untrusted `username` parameter from the HTTP request is concatenated directly into the LDAP filter string without escaping, allowing an attacker to inject LDAP filter syntax and manipulate the query.

## Source

The `username` parameter is retrieved from `request.args.get("username", "")` at line 12, which is untrusted HTTP input. This value flows directly into the filter construction at line 17: `search_filter = "(uid=" + username + ")"`, and is passed to `conn.search()` at line 20, which is the sink.

An attacker can provide payloads like `*` (to match any user), `admin*` (prefix wildcard), or `*)(cn=*` (to inject additional filter conditions) to bypass access controls or extract unintended directory data.

## Fix

**Vulnerable code (lines 1-23):**
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

    search_filter = "(uid=" + username + ")"  # VULNERABLE: string concatenation without escaping

    conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])

    entries = conn.entries
    conn.unbind()
```

**Fixed code:**
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
```

## Explanation

The fix adds the `escape_filter_chars()` function from `ldap3.utils.conv` to the imports and applies it to the `username` parameter before concatenating it into the LDAP filter string. This escaping function neutralizes LDAP metacharacters (`*`, `(`, `)`, `\`, and NUL) that hold syntactic meaning in RFC 4515 filter expressions. When the attacker's input passes through this escaping function, special characters are converted to their escaped representations, preventing the injection of new filter clauses or wildcards. For example, `*` becomes `\2a`, `(` becomes `\28`, and `)` becomes `\29`, ensuring they are treated as literal characters in the filter value rather than LDAP syntax. This eliminates the injection vector while preserving the search functionality for legitimate usernames.

## Behaviour changes

None. The `escape_filter_chars()` function preserves the search semantics by escaping only the metacharacters that have special meaning in LDAP filters. Legitimate usernames are unaffected. The return value of `conn.search()`, the handling of `conn.entries`, and the unbind operation all remain unchanged. The fix maintains the existing contract of the sink while closing the injection vulnerability.
