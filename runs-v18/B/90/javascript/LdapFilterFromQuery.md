## Verdict

Exploitable

## Source

User-controlled input from `req.query.username` (line 7), passed unsanitized to LDAP filter construction (line 11).

## Fix

### File: LdapFilterFromQuery.js

```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  const filter = new ldap.EqualityFilter({ attribute: 'uid', value: username });

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

The original code concatenates user input directly into an LDAP filter string (`'(uid=' + username + ')'`), allowing attackers to inject LDAP filter syntax characters like `*`, `(`, and `)` to modify the query logic. The fix replaces string concatenation with an `EqualityFilter` object (`new ldap.EqualityFilter({ attribute: 'uid', value: username })`). The `EqualityFilter` class automatically escapes special characters according to RFC 4515, preventing the injection. When the filter object is passed to `client.search()`, its `toString()` method produces a safely escaped filter string.

## Behaviour changes

The filter changes from a string to an object, but this is handled transparently by `ldapjs`—the `client.search()` method accepts filter objects and calls `toString()` internally. The escaping applied by `EqualityFilter` preserves the intended query semantics while preventing injection: a username like `admin)(|(objectClass=*` is escaped to `admin\29\28|\28objectClass=\2a`, which no longer terminates the uid term or injects a new clause.
