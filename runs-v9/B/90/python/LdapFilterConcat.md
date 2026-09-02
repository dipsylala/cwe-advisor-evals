## Verdict

exploitable

- CWE ID: CWE-90 (Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection'))
- Location: `LdapFilterConcat.py`, line 20 (sink), filter built at line 17
- Confidence: high

## Source

`request.args.get("username", "")` at line 12 - the Flask `username` query parameter, fully attacker-controlled, with no validation, allowlisting, or escaping applied anywhere before use.

## Fix

**Library recommendation**

The code already depends on `ldap3`, which ships the escaping function needed for this fix (`ldap3.utils.conv.escape_filter_chars`) - no new dependency or version bump is required. Confirm the resolved `ldap3` version against SCA/dependency-check tooling before merging, per standard practice, but no minimum version is being asserted here since the loaded guidance does not carry one for this API.

**Vulnerable code**

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

    search_filter = "(uid=" + username + ")"  # VULNERABLE: raw concatenation into LDAP filter

    # SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
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
```

**Fixed code**

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
```

## Explanation

`escape_filter_chars()` applies RFC 4515 escaping to `username` before it is concatenated into the filter string, converting `*`, `(`, `)`, backslash, and NUL into their `\XX` hex-escaped forms so they are treated as literal characters by the LDAP server's filter parser rather than as filter syntax. This closes the injection point: an attacker can no longer close the `(uid=...)` term early, splice in additional filter clauses (e.g. an `objectClass` OR-clause), or turn the equality test into an unauthenticated wildcard match by supplying a bare `*`. The fix is applied at the exact point identified in Step 4 - the concatenation on the line building `search_filter` - and leaves the rest of the request handling (base DN, attribute list, connection handling) untouched. No allowlist substitution is layered on top here: the guidance's primary defence for this sink is filter escaping, and a username allowlist is not implied by the existing code (no pattern such as alphanumeric-only is established elsewhere in this file), so adding one would be a broader change than the finding requires.

## Behaviour changes

none - `escape_filter_chars()` is the identity transform for any username that contains no LDAP filter metacharacters (the normal case), so legitimate lookups behave exactly as before. For a username that does contain `*`, `(`, `)`, `\`, or NUL, the previous code either threw an LDAP filter syntax error or, worse, executed the attacker's injected filter; the fixed code instead treats those characters literally and searches for a `uid` containing them verbatim, which for a real directory will simply return no match (`404 user not found`) since usernames do not normally contain such characters - this is the intended effect of closing the weakness, not an unrelated behaviour change. The sink's arguments (`BASE_DN`, `attributes=["cn", "mail", "uid"]`), its return value handling, and its failure behaviour are all unchanged from the original.

## Assumptions

None - the language (Python), sink (`ldap3.Connection.search()`), and applicable guidance (`cwe/90/python/INDEX.md`) were all unambiguous from the file's imports and the finding's stated location.
