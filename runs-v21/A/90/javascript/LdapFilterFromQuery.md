## Verdict
CONFIRMED

## Source
Line 7: `const username = req.query.username;` — untrusted input from query parameters

## Fix
### File: LdapFilterFromQuery.js
```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

// Helper function to escape LDAP filter special characters
const escapeLdapFilter = (str) => {
  if (!str) return '';
  return String(str)
    .replace(/\\/g, '\\5c')  // backslash
    .replace(/\*/g, '\\2a')  // asterisk
    .replace(/\(/g, '\\28')  // open paren
    .replace(/\)/g, '\\29')  // close paren
    .replace(/\x00/g, '\\00'); // null character
};

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  const filter = '(uid=' + escapeLdapFilter(username) + ')';

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
The vulnerability was introduced by directly concatenating user-supplied input into an LDAP filter string at line 11. LDAP metacharacters (like `*`, `(`, `)`, `\`) have special meaning in filter expressions and can be abused to break query syntax or alter query logic.

The fix adds an `escapeLdapFilter()` helper function that escapes all LDAP special characters by converting them to their hex-escape sequences (e.g., `*` becomes `\2a`). This prevents injection attacks by ensuring that user input is always treated as literal data, not as filter syntax.

The escaping is applied at line 21 where the filter is constructed, ensuring that any username value is safely neutralized before reaching the `client.search()` sink.
