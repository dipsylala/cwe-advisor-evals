## Verdict

**Confirmed exploitable.** The filter is constructed by string concatenation of untrusted user input without escaping. An attacker can inject LDAP metacharacters (`*`, `(`, `)`) to modify the query logic, bypass authentication, or retrieve unauthorized directory data.

## Source

Line 14: `const filter = '(uid=' + username + ')';`

The `username` parameter comes from `req.query.username` (line 7) and is unsanitized user input from an HTTP request. It is concatenated directly into the LDAP filter string, which is then passed to `client.search()` on line 22.

Exploit example: A request with `?username=admin)(|(uid=*` would transform the filter to `(uid=admin)(|(uid=*))`, making it a two-term OR expression that matches any entry with a uid field.

## Fix

Replace string concatenation with an LDAP filter object that escapes the value automatically. Use `ldapjs` 3.x's `EqualityFilter` class:

```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  // Build filter using EqualityFilter - escapes metacharacters automatically
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

If the `ldapjs` version does not expose filter classes, use the `ldap-escape` package (verified current as of June 2022) with a tagged template:

```javascript
const ldapEscape = require('ldap-escape');
const filter = ldapEscape.filter`(uid=${username})`;
```

## Explanation

`ldapjs` 3.x's `EqualityFilter` class (and its sibling filter classes like `AndFilter`, `OrFilter`, `SubstringFilter`) separates query structure from user data. When the filter object is passed to `client.search()`, its `toString()` method applies RFC 4515 escaping to the value field, converting LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) to their two-digit hex escape sequences (e.g., `(` becomes `\28`, `)` becomes `\29`).

This escaping ensures that metacharacters in the user input cannot close or open filter clauses. The exploit payload `admin)(|(uid=*` is escaped to `admin\29\28|\28uid=\2a`, which is treated as a literal string value matching the attribute, not as filter syntax.

The fix moves from string concatenation (which has no escaping) to using filter objects as the canonical safe pattern in `ldapjs`. This eliminates the injection point entirely while preserving the search functionality.

## Behaviour changes

- The filter is now an object (`EqualityFilter` instance) instead of a string. The `client.search()` API accepts filter objects and handles encoding automatically.
- Special characters in the username are escaped and treated as part of the value, not filter syntax. A username containing `*`, `(`, or `)` now matches literally instead of being interpreted as LDAP operators.
- Search results and error handling remain unchanged. The response structure and HTTP status codes are identical.

Test: Confirm that a request with `?username=admin)(|(uid=*` returns no results (the literal string is not a valid uid) rather than returning all entries or causing an error. Confirm that a valid username like `alice` still returns the expected directory entry.
