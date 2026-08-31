## Verdict

Real vulnerability. Untrusted HTTP query parameter flows unsanitized into LDAP filter syntax, enabling attackers to inject special characters that modify query logic and access or bypass directory restrictions.

## Source

`req.query.username` (line 7) flows directly into filter string concatenation at line 11, then passed to `client.search()` at line 22. The source is attacker-controlled via HTTP GET query parameter and reaches the LDAP query sink with no escaping or validation.

## Fix

Define and apply an RFC 4515 escaping function before concatenating the username into the filter string. Add input validation to restrict username to a known-safe pattern:

```javascript
// Escape LDAP special characters per RFC 4515
// Replace backslash first so inserted escape sequences aren't re-escaped
function escapeLdapFilter(str) {
  return str.replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

// Validate username against allowlist pattern
function isValidUsername(username) {
  // Allow only alphanumeric, dash, underscore, period
  return /^[a-zA-Z0-9._-]+$/.test(username) && username.length > 0 && username.length <= 64;
}

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  // Validate before use
  if (!isValidUsername(username)) {
    return res.status(400).json({ error: 'invalid username format' });
  }

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  // Escape special LDAP characters in filter
  const filter = '(uid=' + escapeLdapFilter(username) + ')';

  const opts = {
    filter,
    scope: 'sub',
    attributes: ['uid', 'cn', 'mail'],
  };

  const entries = [];

  client.search('ou=people,dc=example,dc=com', opts, (err, search) => {
    if (err) {
      client.unbind();
      return res.status(500).json({ error: 'directory search failed' });
    }

    search.on('searchEntry', (entry) => entries.push(entry.pojo));
    search.on('end', () => {
      client.unbind();
      res.json(entries);
    });
  });
});
```

## Explanation

The vulnerability occurs because `req.query.username` is concatenated directly into the LDAP filter string using string concatenation without escaping or validation. LDAP filter syntax (RFC 4515) assigns special meaning to `*` (wildcard), `(` and `)` (clause delimiters), `\` (escape character), and NUL (terminator). An attacker can inject these characters to alter the filter logic—for example, a username like `*` changes the filter to `(uid=*)` which matches any entry, or `*)(uid=admin` produces `(uid=*)(uid=admin` which retrieves the admin entry.

The fix applies two layers of defence:

1. **RFC 4515 escaping:** Escapes all five special LDAP characters by replacing each with backslash followed by its two-digit hex code. The backslash itself is escaped first to prevent the inserted escape sequences from being re-escaped. This transforms any injected syntax characters into literal data that the LDAP parser treats as part of the value.

2. **Allowlist validation:** Restricts username input to alphanumeric characters, dash, underscore, and period, and enforces length bounds. The allowlist gate runs before escaping and rejects inputs that do not match the expected format, stopping obvious attack attempts before they reach the LDAP layer.

Together, these prevent the filter string from being modified by attacker input, ensuring the query structure remains `(uid=<escaped-username>)` regardless of the username's content.

## Behaviour changes

- Invalid usernames (those not matching the allowlist pattern) are now rejected with HTTP 400, instead of being passed to the LDAP query.
- Valid usernames containing LDAP special characters are now escaped, preserving their literal value in the search instead of modifying the query structure.
- No change to successful search results, error handling, or response format for valid queries.
- Memory and CPU impact is negligible (single-pass string escaping).
