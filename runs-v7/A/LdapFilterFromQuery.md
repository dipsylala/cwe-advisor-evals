## Verdict

Confirmed. The vulnerability exists at line 11 where user-controlled input (`username` from `req.query.username`) is directly concatenated into an LDAP filter string without sanitization.

## Source

Line 7 reads the untrusted input: `const username = req.query.username;`

Line 11 sinks the input unsanitized into the filter: `const filter = '(uid=' + username + ')';`

An attacker can inject LDAP metacharacters like `*`, `(`, `)`, `&`, `|`, and `!` to modify the query logic. For example, a username of `*)(uid=*))(&(uid=*` would transform the filter into `(uid=*)(uid=*))(&(uid=*)`, matching any directory entry and bypassing access controls.

## Fix

Use `ldapjs.escapeFilterValue()` to escape the username before inserting it into the filter:

```javascript
const username = req.query.username;

const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

const filter = '(uid=' + ldap.escapeFilterValue(username) + ')';
```

The `escapeFilterValue()` function properly encodes LDAP special characters, rendering injection attempts harmless. The escaped value produces literal string matching only.

## Explanation

LDAP injection exploits occur when user input controls the structure of an LDAP query filter. The filter syntax uses special characters — `*` (wildcard), `(` and `)` (grouping), `&` (AND), `|` (OR), `!` (NOT) — that change query semantics when unescaped. Concatenating raw user strings allows attackers to break out of the intended filter structure and craft queries that match unintended directory entries.

The `ldapjs` library provides `escapeFilterValue()` as the standard defense. It replaces special characters with their hex-encoded equivalents (e.g., `*` → `\2a`), ensuring the input is treated as a literal string value rather than filter syntax. This is the primary and sufficient mitigation for LDAP injection in Node.js applications using `ldapjs`.
