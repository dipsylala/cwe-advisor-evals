## Verdict

Exploitable. User input from `req.query.username` (line 7) is concatenated directly into the LDAP filter string without escaping, allowing an attacker to inject LDAP metacharacters and modify query logic.

## Source

Line 7: `const username = req.query.username;`

Untrusted user input from HTTP query parameter flows to filter construction on line 11.

## Fix

**Vulnerable code (line 11):**
```javascript
const filter = '(uid=' + username + ')';
```

**Fixed code:**
```javascript
// Escape LDAP special characters per RFC 4515
function escapeLdapFilter(value) {
  if (value === null || value === undefined) return '';
  // Escape backslash first to avoid double-escaping
  return String(value)
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

const escapedUsername = escapeLdapFilter(username);
const filter = '(uid=' + escapedUsername + ')';
```

Alternatively, use the `ldap-escape` library (add to `package.json`):
```javascript
const escape = require('ldap-escape');

const filter = '(uid=' + escape(username) + ')';
```

## Explanation

The fix applies RFC 4515 LDAP filter escaping to the username before constructing the filter string. This neutralizes the LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) that would otherwise allow query structure manipulation. Each special character is replaced with a backslash followed by its two-digit hex code (e.g., `*` becomes `\2a`). The backslash itself must be escaped first to prevent inserted escape sequences from being escaped again. The escaped value is then safe to concatenate into the filter string without altering query logic.

## Behaviour changes

None. The escape function preserves the original username value within the filter as a literal string. The LDAP search still returns entries matching the escaped value, with identical scope, attributes, and error handling.
