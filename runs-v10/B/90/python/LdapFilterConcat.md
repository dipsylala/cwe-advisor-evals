## Verdict

exploitable

## Source

Line 12: `username = request.args.get("username", "")` receives untrusted user input from the HTTP request.

## Fix

**Vulnerable code (line 17-20):**
```python
search_filter = "(uid=" + username + ")"

# SAST FINDING: CWE-90 (Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')) reported here. Sink is the next statement.
conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
```

**Fixed code:**
```python
from ldap3.utils.conv import escape_filter_chars

# ... in lookup_user() function:
escaped_username = escape_filter_chars(username)
search_filter = "(uid=" + escaped_username + ")"

conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
```

**Import addition at top of file:**
Add `from ldap3.utils.conv import escape_filter_chars` to the imports.

## Explanation

The vulnerability arises from direct string concatenation of the user-supplied `username` into the LDAP filter without escaping. An attacker can inject LDAP filter syntax by providing a username containing special characters like `*`, `(`, `)`, or backslash. For example, a username of `*)(uid=*))(&(uid=*` would transform the filter into `(uid=*)(uid=*))(&(uid=*))`, allowing unauthorized access or information disclosure. The fix applies `escape_filter_chars()` from ldap3 to neutralize these special characters according to RFC 4515, converting them to escaped sequences that are treated as literal data rather than LDAP syntax operators. This ensures the filter structure remains intact and user input cannot modify the query logic.

## Behaviour changes

none
