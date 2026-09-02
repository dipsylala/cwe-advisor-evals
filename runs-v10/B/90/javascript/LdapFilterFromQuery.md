## Verdict

Exploitable. The `username` parameter from the query string is concatenated directly into the LDAP filter without escaping, allowing injection of LDAP metacharacters to alter query logic.

## Source

`req.query.username` (line 7) - untrusted user input from the HTTP query parameter. The value flows without validation into the filter string concatenation on line 11.

## Fix

**Vulnerable code (original):**

```javascript
const filter = '(uid=' + username + ')';
```

**Fixed code using RFC 4515 escaping:**

```javascript
function escapeLdapFilter(input) {
  return input.replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

const filter = '(uid=' + escapeLdapFilter(username) + ')';
```

**Alternative: using the `ldap-escape` package (recommended for production):**

```javascript
const ldapEscape = require('ldap-escape');

const filter = '(uid=' + ldapEscape.filter(username) + ')';
```

Note: If using `ldap-escape`, add it to `package.json` dependencies.

## Explanation

The original code constructs an LDAP filter by concatenating the user-supplied username directly into the filter string without escaping. This allows an attacker to inject LDAP metacharacters (`*`, `(`, `)`, `\`, and NUL) to modify the query structure. For example, a username of `admin*` produces the filter `(uid=admin*)`, which matches any uid starting with "admin" instead of an exact match. A more sophisticated attack like `*)(uid=*))(&(uid=*` can close the filter prematurely and alter the query logic entirely.

RFC 4515 specifies that these special characters must be escaped as backslash-followed-by-two-digit hex codes: `*` → `\2a`, `(` → `\28`, `)` → `\29`, `\` → `\5c`, NUL → `\00`. The fix applies this escaping to the username before concatenation, ensuring the entire value is treated as literal data rather than LDAP filter syntax. This prevents injection attacks while still allowing legitimate usernames with special characters to match correctly.

## Behaviour changes

**None.** The fix preserves the original search semantics. A valid username that happens to contain LDAP special characters (e.g., "john*smith") will be escaped and searched as a literal value. Search results and return values remain unchanged. The only observable difference is that LDAP injection payloads no longer alter the query structure—they are now treated as literal strings to match, so they will return no results (as intended).

