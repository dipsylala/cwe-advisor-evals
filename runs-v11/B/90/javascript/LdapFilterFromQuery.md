## Verdict

Exploitable. User-controlled input from `req.query.username` is concatenated directly into the LDAP filter string without escaping, allowing an attacker to inject LDAP syntax such as `*)(&(objectClass=*` to modify query logic and access unauthorized directory data.

## Source

`req.query.username` (line 7) flows unvalidated to line 11 where it is concatenated into the filter string, then used at line 22 in `client.search()`.

## Fix

**Option 1: Using the `ldap-escape` library (recommended)**

```javascript
const express = require('express');
const ldap = require('ldapjs');
const { escapeFilter } = require('ldap-escape');

const router = express.Router();

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  // Escape the username per RFC 4515 to prevent LDAP injection
  const escapedUsername = escapeFilter([username])[0];
  const filter = '(uid=' + escapedUsername + ')';

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

**Option 2: Manual RFC 4515 escaping without external dependency**

```javascript
const express = require('express');
const ldap = require('ldapjs');

// Helper function to escape LDAP filter values per RFC 4515
function escapeLdapFilterValue(value) {
  if (!value) return value;
  // Escape backslash first so subsequent escapes are not double-escaped
  return value
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

const router = express.Router();

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  // Escape the username per RFC 4515 to prevent LDAP injection
  const escapedUsername = escapeLdapFilterValue(username);
  const filter = '(uid=' + escapedUsername + ')';

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

The vulnerability arises from concatenating untrusted user input directly into an LDAP filter without escaping special characters that hold meaning in LDAP query syntax. LDAP uses `(`, `)`, `*`, `\`, and NUL to construct filter expressions; an attacker injecting these can close one filter clause and open another to modify the query logic. The fix applies RFC 4515 escaping to convert these metacharacters to their hexadecimal equivalents (`\28`, `\29`, `\2a`, `\5c`, `\00`), which are then interpreted as literal characters rather than LDAP syntax. Escaping the backslash first prevents the escape sequences themselves from being double-escaped. This ensures only the intended filter structure is parsed, preventing injection attacks while preserving legitimate usernames.

## Behaviour changes

None. The escaping transforms the username into a form that the LDAP parser treats as a literal value, which is the intended behavior of the fix. The filter is still a string passed to `client.search()` in the same `opts` parameter, so the sink's contract and error handling remain unchanged. Test with injection payloads like `*)(&(objectClass=*` to confirm they return no matches rather than matching all entries.
