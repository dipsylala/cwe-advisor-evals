## Verdict

Exploitable. The `username` parameter from the HTTP request (line 12) flows directly into the LDAP filter string on line 17 without escaping, allowing an attacker to inject LDAP metacharacters and modify the query structure.

## Source

`request.args.get("username", "")` on line 12 — untrusted user input from the HTTP request query string.

## Fix

**Vulnerable code (lines 12, 17, 20):**
```python
username = request.args.get("username", "")
# ...
search_filter = "(uid=" + username + ")"
# SAST FINDING: CWE-90
conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
```

**Fixed code:**
```python
from ldap3.utils.conv import escape_filter_chars

# ... in the lookup_user function ...
username = request.args.get("username", "")

# Validate input against allowlist pattern
if not username or not all(c.isalnum() or c in '-_.' for c in username):
    return jsonify({"error": "invalid username format"}), 400

# Escape special LDAP characters in the filter value
escaped_username = escape_filter_chars(username)
search_filter = "(uid=" + escaped_username + ")"

conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
```

## Explanation

The fix addresses the LDAP injection vulnerability by applying two layers of defence: first, an allowlist validation that restricts the username to alphanumeric characters and a narrow set of safe symbols (hyphen, underscore, period), rejecting any input that doesn't match; second, escaping the validated username using `ldap3`'s built-in `escape_filter_chars()` function, which neutralizes LDAP metacharacters (`*`, `(`, `)`, backslash, NUL) by encoding them as their RFC 4515 hex representation. This prevents attackers from breaking out of the filter structure even if the allowlist is bypassed. The validation layer is added early to fail fast on obviously malicious input, while the escaping layer ensures that even edge cases are handled safely before the filter reaches `conn.search()`.

## Behaviour changes

- **Import added**: `escape_filter_chars` imported from `ldap3.utils.conv` to provide the escaping mechanism.
- **Input validation added**: A check is introduced to reject usernames containing characters outside the allowlist (alphanumeric, hyphen, underscore, period). This returns a 400 Bad Request response instead of executing the query, which is a defensive change that prevents obviously malicious input from reaching the query sink. This is acceptable because legitimate usernames typically match this pattern; the validation documents the expected format.
- **Return value on validation failure**: The function returns early with a JSON error response (400) when validation fails, which is different from the original behavior that would attempt the search with any username. This is intentional — rejecting invalid input before it reaches LDAP is more secure than attempting to sanitize it later.
- **Filter construction unchanged in semantics**: The filter structure remains `(uid=<username>)`, but the username is now escaped, so special characters are rendered harmless without changing the query logic. The search behavior is unchanged for valid usernames.
