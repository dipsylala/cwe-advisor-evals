## Verdict

Exploitable

## Source

Line 7: `const username = req.query.username;` - untrusted user input from Express query parameter

## Fix

### File: LdapFilterFromQuery.js

```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  // Validate username with allowlist - restrict to alphanumeric and common safe characters
  if (!username || !/^[a-zA-Z0-9._-]+$/.test(username)) {
    return res.status(400).json({ error: 'invalid username' });
  }

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  // Use ldapjs EqualityFilter object instead of string concatenation to prevent LDAP injection
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

  // SAST FINDING: CWE-90 (Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')) reported here. Sink is the next statement.
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

The vulnerability exists on line 11 of the original code: the username query parameter is directly concatenated into an LDAP filter string without sanitization. An attacker can inject LDAP metacharacters to modify query logic—for example, `admin*)(&(uid=*` would turn `(uid=admin*)(&(uid=*))` into two independent filter expressions, allowing unauthorized access. The fix replaces string concatenation with `ldapjs`'s built-in `EqualityFilter` object, which automatically escapes RFC 4515 special characters (`*`, `(`, `)`, `\`, and NUL) when the filter is constructed. The allowlist validation (alphanumeric, dot, underscore, hyphen) provides defence-in-depth by rejecting usernames with unexpected characters before they reach the filter. The `EqualityFilter` object is passed directly to `client.search()` in the opts, where ldapjs handles escaping when converting the filter to its wire format.

## Behaviour changes

- Added input validation: requests with empty or invalid usernames now return HTTP 400 instead of proceeding to the LDAP search. This is a new validation gate that changes the error contract for malformed input.
- Changed filter construction from a string to a `EqualityFilter` object. The object's `toString()` method applies RFC 4515 escaping transparently when needed, so the query sent to the LDAP server contains escaped sequences (e.g., `\2a` for `*`). This does not change the intent of the search or the data returned by the `client.search()` callback; it only changes how untrusted input is represented in the wire protocol.
- No change to the `client.search()` arguments, scope, attributes, or callback flow; the returned entries and error handling remain identical.

