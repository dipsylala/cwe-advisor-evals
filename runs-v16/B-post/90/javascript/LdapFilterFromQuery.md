## Verdict
Exploitable

## Source
`req.query.username` (line 7) - attacker-controlled query parameter passed through to LDAP filter construction without sanitization

## Fix

**Vulnerable code (original, line 11):**
```javascript
const filter = '(uid=' + username + ')';
```

**Fixed code:**
```javascript
const filter = new ldap.EqualityFilter({
  attribute: 'uid',
  value: username
});
```

Complete remediated route:
```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  // Use EqualityFilter object with RFC 4515 escaping instead of string concatenation
  const filter = new ldap.EqualityFilter({
    attribute: 'uid',
    value: username
  });

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
The vulnerability lies in concatenating untrusted user input directly into an LDAP filter string on line 11. An attacker can inject LDAP metacharacters (`*`, `(`, `)`, `\`) to break out of the filter structure and modify query logic. For example, a username like `*)(uid=*))(|(uid=*` would create an unintended filter that matches all entries. The fix replaces string concatenation with `ldapjs`'s built-in `EqualityFilter` object, which automatically applies RFC 4515 escaping to the value parameter. This ensures that special characters are encoded as backslash sequences (e.g., `\2a` for `*`, `\28` for `(`) and treated as literal data rather than filter operators. The filter object is passed directly to `client.search()`, which properly constructs the filter string with escaping applied.

## Behaviour changes
None. The `ldapjs` `client.search()` API accepts both string filters and filter objects. When passed a filter object, it internally calls `toString()` on the object to produce an escaped filter string, preserving the same async callback behavior, error handling, and result format as the original code. The searchEntry events, unbind() call, and JSON response remain identical.
