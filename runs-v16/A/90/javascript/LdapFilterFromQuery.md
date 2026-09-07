## Verdict
The code is vulnerable to LDAP injection. At line 11, the LDAP filter is constructed by directly concatenating the unsanitized `username` query parameter into the filter string. An attacker can inject LDAP metacharacters (such as `*`, `(`, `)`, `&`, `|`) to manipulate the filter logic and bypass authentication or extract unintended directory entries.

## Source
Line 11: `const filter = '(uid=' + username + ')';`

The `username` variable originates from the untrusted query parameter `req.query.username` (line 7) and is concatenated directly into the LDAP filter without sanitization.

## Fix
Use `ldapjs`'s built-in `escapeFilterAttribute()` function to sanitize the username before embedding it in the filter:

```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  const filter = '(uid=' + ldap.escapeFilterAttribute(username) + ')';

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

module.exports = router;
```

## Explanation
LDAP injection occurs when untrusted input is concatenated into an LDAP filter without escaping. LDAP filters use metacharacters such as `*` (wildcard), `()` (grouping), `&` (AND), `|` (OR), and `!` (NOT) to construct complex queries. An attacker can inject these characters to alter filter semantics.

For example, if `username` is set to `*)(uid=*`, the filter becomes `(uid=*)(uid=*)`, which matches any user regardless of the uid value and can lead to authentication bypass or unauthorized data disclosure.

The `escapeFilterAttribute()` function provided by ldapjs properly escapes special characters in filter values, converting them to their hex-encoded equivalents (e.g., `*` becomes `\2a`, `(` becomes `\28`, `)` becomes `\29`). This ensures the user input is treated as data, not filter syntax, neutralizing the injection.
