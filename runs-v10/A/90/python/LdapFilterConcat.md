## Verdict
Confirmed. The LDAP filter is constructed by concatenating unsanitized user input directly into the filter string, allowing an attacker to inject LDAP metacharacters and alter query logic.

## Source
Line 12: `username = request.args.get("username", "")` — untrusted input from HTTP query parameter.

## Fix
```python
from ldap3 import Server, Connection, ALL
from ldap3.utils.dn import escape_filter_chars

@app.route("/directory/lookup")
def lookup_user():
    username = request.args.get("username", "")
    
    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, auto_bind=True)
    
    # Escape LDAP filter special characters in user input
    safe_username = escape_filter_chars(username)
    search_filter = f"(uid={safe_username})"
    
    conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
    # ... rest of code unchanged
```

## Explanation
The vulnerability exists because `username` is concatenated directly into the LDAP filter string on line 17 without escaping LDAP metacharacters. An attacker can inject characters like `*`, `(`, `)`, and `\` to break out of the intended filter logic — for example, submitting `*)(uid=*` would transform the filter to `(uid=*)(uid=*)`, matching all users.

The fix applies `escape_filter_chars()` from `ldap3.utils.dn`, which neutralizes LDAP special characters by escaping them so they are treated as literal data rather than syntax. This ensures the username is safely incorporated into the filter query, preventing injection attacks while preserving legitimate searches.
