## Verdict
The vulnerability is confirmed. User input from `req.query.username` is directly concatenated into an LDAP filter string without escaping, allowing an attacker to inject LDAP filter syntax and manipulate the query logic.

## Source
Line 7-11: The `username` parameter is extracted from the query string and concatenated directly into the LDAP filter without escaping LDAP special characters.

```
const username = req.query.username;
const filter = '(uid=' + username + ')';
```

An attacker can exploit this by providing input like `*))(&(uid=*` to create a filter like `(uid=*))(&(uid=*))`, bypassing intended access controls.

## Fix

### File: LdapFilterFromQuery.js

```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

function escapeLdapFilter(input) {
  if (!input) return input;
  
  const escapeMap = {
    '\x00': '\\00',
    '*': '\\2a',
    '(': '\\28',
    ')': '\\29',
    '\\': '\\5c',
  };
  
  return input.replace(/[\x00*()\\]/g, (char) => escapeMap[char]);
}

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
The fix introduces an `escapeLdapFilter()` function that neutralizes LDAP special characters by escaping them with backslash notation as per RFC 4515 (LDAP filter syntax). The five characters that carry special meaning in LDAP filters are escaped:

- `*` (0x2a) — wildcard metacharacter
- `(` (0x28) — opening parenthesis for logical grouping
- `)` (0x29) — closing parenthesis for logical grouping
- `\` (0x5c) — escape character itself
- `\x00` (NUL) — string terminator

When the username is escaped before filter construction, an attacker's injected filter syntax is treated as literal characters, preventing query manipulation. For example, `*))(&(uid=*` becomes `\2a\29\29\28&(uid=\2a`, which the LDAP server interprets as a literal search string rather than filter syntax.
