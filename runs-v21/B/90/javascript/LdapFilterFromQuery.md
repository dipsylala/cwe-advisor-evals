## Verdict

Exploitable. Untrusted user input from the query parameter `username` is concatenated directly into an LDAP filter string without escaping or validation. An attacker can inject LDAP metacharacters to alter the query logic, leading to authentication bypass or unauthorized data access.

## Source

The vulnerability originates at line 7 where the untrusted `username` parameter is extracted from the request query string:
```javascript
const username = req.query.username;
```

This value flows into the filter construction at line 11:
```javascript
const filter = '(uid=' + username + ')';
```

The concatenated filter string is then passed to `client.search()` at line 22, which executes the potentially modified LDAP query.

## Fix

Replace string concatenation with an LDAP filter object using `ldapjs`'s `EqualityFilter` class. The filter object automatically escapes special characters when converted to a string by ldapjs, preventing metacharacter injection.

### File: LdapFilterFromQuery.js

```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

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

The original code at line 11 concatenated the user input directly into the LDAP filter string: `'(uid=' + username + ')'`. This allowed attackers to inject LDAP metacharacters:
- `*` converts an equality test to a presence match (returns all entries with the attribute)
- `)` closes the current filter clause, allowing injection of new logic
- `(` opens a new filter clause
- `\` and NUL can further alter parsing

The fix replaces string concatenation with `ldapjs`'s `EqualityFilter` class, which:
1. Takes the attribute name and value as separate, structured properties
2. Automatically escapes RFC 4515 special characters (`*`, `(`, `)`, `\`, NUL) when the filter is converted to a string internally
3. Maintains the same search interface and callback behavior
4. Ensures the value is treated as data, not as query syntax

An attacker providing `username = "admin)(&"` will now produce `(uid=admin\29\28&)` instead of `(uid=admin)(&)`, preventing the injection.

## Behaviour changes

None. The filter object is passed to `client.search()` in the `opts` parameter where a string filter was previously passed. The ldapjs library accepts both forms and handles the conversion transparently. The search interface, error handling, result handling, and return value to the client remain identical. No API changes or functional behavior alterations occur.

