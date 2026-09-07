## Verdict

Exploitable. The `username` parameter from the HTTP query string is concatenated directly into an LDAP filter string without escaping, allowing attackers to inject special LDAP characters (`*`, `(`, `)`, `\`, NUL) to modify the query logic and access or enumerate directory entries.

## Source

Line 12: `username = request.args.get("username", "")` - user-controlled HTTP query parameter, attacker-supplied.

## Fix

**Vulnerable code (line 17-20):**
```python
search_filter = "(uid=" + username + ")"

# ...
conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
```

**Fixed code:**
```python
from ldap3.utils.conv import escape_filter_chars

# ...
escaped_username = escape_filter_chars(username)
search_filter = "(uid=" + escaped_username + ")"

conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
```

Add the import at the top of the file:
```python
from ldap3.utils.conv import escape_filter_chars
```

## Explanation

The fix escapes all special LDAP filter characters in the username using `escape_filter_chars()` before interpolating it into the filter string. This function implements RFC 4515 escaping, converting metacharacters (`*`, `(`, `)`, `\`, NUL) into their hex-escaped equivalents so they are treated as literal characters rather than filter syntax. For example, `admin*` becomes `admin\2a`, preventing the `*` from being interpreted as a presence test wildcard. The escaping ensures the username is always treated as a filter value, not as filter structure, and eliminates the ability to break out of the `(uid=...)` term and inject additional clauses.

## Behaviour changes

None. The `conn.search()` method receives the same filter structure and returns the same result set. The escaping is transparent to the caller—only the character interpretation changes from structural to literal, which is the intended behaviour for user-supplied values in LDAP filters.
