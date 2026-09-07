## Verdict
Exploitable

## Source
`req.query.username` at line 7 — untrusted user input from query parameters

## Fix

**Vulnerable code:**
```javascript
const filter = '(uid=' + username + ')';
```

**Fixed code:**
```javascript
const filter = new ldap.EqualityFilter({ attribute: 'uid', value: username });
```

## Explanation
The vulnerability occurs because user input is directly concatenated into an LDAP filter string without escaping. LDAP special characters like `*`, `(`, `)`, `\`, and NUL have syntactic meaning in filter expressions, allowing an attacker to inject arbitrary query logic. For example, `admin)(&` would transform `(uid=admin)(&)` into two separate filter clauses, enabling authentication bypass or unintended data access.

The fix uses `ldapjs` 3.x's `EqualityFilter` class to construct the filter as an object rather than a string. The `EqualityFilter` constructor automatically applies RFC 4515 escaping to the user-supplied value, converting special characters to their backslash-hex representation (e.g., `*` → `\2a`, `(` → `\28`). This separates query structure from data and neutralizes the injection vector. The filter object is passed directly to `client.search()`, which accepts both string and object filters.

## Behaviour changes
The filter is now a filter object (`EqualityFilter` instance) instead of a string. Both representations are accepted by `ldapjs`' `client.search()` method, so this is a compatible change. The query scope (`sub`), base DN, and returned attributes remain unchanged. No changes to error handling, response structure, or binding behavior.
