## Verdict

The vulnerability is confirmed and remediable. The code concatenates untrusted HTTP request input directly into an LDAP filter string without escaping, allowing LDAP injection attacks.

## Source

Line 12 receives untrusted input from HTTP request parameters: `username = request.args.get("username", "")`. This value is attacker-controlled and obtained directly from the query string without validation.

## Fix

Replace lines 1-2 and lines 17-20 with:

```python
from flask import Flask, request, jsonify
from ldap3 import Server, Connection, ALL
from ldap3.utils.conv import escape_filter_chars
```

And replace line 17-20 with:

```python
    escaped_username = escape_filter_chars(username)
    search_filter = "(uid=" + escaped_username + ")"

    # CWE-90: Username is now escaped and safe for LDAP query
    conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
```

## Explanation

The fix uses `ldap3.utils.conv.escape_filter_chars()` to neutralize LDAP metacharacters in the username before constructing the filter string. This escaping function encodes the special characters that LDAP filter syntax interprets as operators: `*`, `(`, `)`, `\`, and NUL. An attacker cannot escape this escaping to inject new LDAP query syntax. The escaped value remains a data value within the equality comparison and cannot be interpreted as filter structure. The `conn.search()` call receives a filter string where the username is safe data, not code.

## Behaviour changes

No behaviour changes to legitimate requests. Usernames containing special characters that would previously have been rejected or caused LDAP errors are now correctly handled: a user lookup for "admin*" will search for the literal username "admin*" rather than performing a wildcard match, which is the correct behaviour for a username filter.
