## Verdict

Real LDAP injection vulnerability. User-controlled input from `request.args.get("username")` is directly concatenated into the LDAP search filter on line 17 without escaping, then passed unsanitized to `conn.search()` on line 20. An attacker can inject LDAP filter operators (`*`, `(`, `)`, `&`, `|`) to alter query logic, enumerate users, or bypass authentication.

## Source

Line 17 constructs the LDAP filter by string concatenation:
```python
search_filter = "(uid=" + username + ")"
```

The `username` parameter comes from untrusted user input at line 12:
```python
username = request.args.get("username", "")
```

## Fix

Import and use `escape_filter_chars()` from ldap3 to escape the username before filter construction:

```python
from ldap3 import Server, Connection, ALL, escape_filter_chars

# ... existing code ...

@app.route("/directory/lookup")
def lookup_user():
    username = request.args.get("username", "")
    
    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(server, auto_bind=True)
    
    # Escape special LDAP characters in the username
    escaped_username = escape_filter_chars(username)
    search_filter = "(uid=" + escaped_username + ")"
    
    conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
    # ... rest of function unchanged ...
```

## Explanation

The vulnerability occurs because LDAP filter syntax includes special metacharacters (`*`, `(`, `)`, `&`, `|`, `\`, `/`, NUL) that have meaning in query logic. When user input is directly concatenated into a filter string without escaping, an attacker can inject filter operators to modify the query behavior.

For example, if `username="*"`, the filter becomes `(uid=*)`, which matches any user. If `username="admin)(|(uid=*"`, the filter becomes `(uid=admin)(|(uid=*))`, transforming an equality check into an OR operation that bypasses authentication logic.

The `escape_filter_chars()` function from ldap3 properly escapes these characters by converting them to their hex representation (e.g., `*` becomes `\2a`), ensuring they are treated as literal string data rather than filter operators. This prevents filter injection while preserving the intended search semantics.

