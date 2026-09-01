## Verdict
Exploitable

## Source
Untrusted user input from `request.args.get("username", "")` at line 12, flowing directly into the LDAP filter construction at line 17 via string concatenation without sanitization.

## Fix
**Vulnerable code:**
```python
username = request.args.get("username", "")
search_filter = "(uid=" + username + ")"  # CWE-90: Direct concatenation of untrusted input
conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
```

**Fixed code:**
```python
from ldap3.utils.conv import escape_filter_chars

username = request.args.get("username", "")
escaped_username = escape_filter_chars(username)
search_filter = f"(uid={escaped_username})"
conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
```

## Explanation
The original code constructs the LDAP filter by concatenating untrusted user input directly into the filter string, allowing attackers to inject LDAP metacharacters. The fix uses `escape_filter_chars()` from `ldap3.utils.conv` to properly escape all LDAP filter special characters (`*`, `(`, `)`, `\`, NUL) in the username value before constructing the filter. This prevents attackers from modifying the query structure and ensures the username is treated as data rather than filter syntax. The escaping preserves the intended query semantics while safely neutralizing injection vectors.

## Behaviour changes
None. The `escape_filter_chars()` function escapes special LDAP characters but preserves alphanumeric and most common characters unchanged. The `conn.search()` call receives a properly formatted filter string and behaves identically to the original, returning the same result set for valid, non-malicious usernames.
