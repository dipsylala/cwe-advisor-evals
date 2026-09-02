## Verdict

Confirmed. `req.query.username` is concatenated directly into an LDAP search filter string with no escaping, allowing an attacker to inject LDAP filter metacharacters and alter the query's logic (classic LDAP filter injection, e.g. supplying `*)(uid=*))(|(uid=*` to broaden or bypass the intended `uid` match).

## Source

`req.query.username` (Express query-string parameter) in `router.get('/directory/lookup', ...)`, `LdapFilterFromQuery.js` line 7.

## Fix

```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

// RFC 4515 section 3: escape each LDAP filter metacharacter as \XX (hex).
function escapeLdapFilterValue(value) {
  return String(value).replace(/[\\*()\0/]/g, (ch) => {
    return '\\' + ch.charCodeAt(0).toString(16).padStart(2, '0');
  });
}

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  const filter = '(uid=' + escapeLdapFilterValue(username) + ')';

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

The vulnerable line built the filter with plain string concatenation: `'(uid=' + username + ')'`. Because LDAP filters (RFC 4515) treat `*`, `(`, `)`, `\`, and NUL as structural metacharacters, an attacker-controlled `username` containing any of these can close the intended `uid` clause early and append new filter terms — for example a value of `*)(|(uid=*` turns the filter into `(uid=*)(|(uid=*))`, which most LDAP servers evaluate as an always-true or attacker-chosen predicate, exposing directory entries the query was not meant to return (and, depending on downstream use, enabling authentication bypass).

The fix adds `escapeLdapFilterValue`, which walks the untrusted value and replaces every RFC 4515-reserved byte (`\`, `*`, `(`, `)`, and NUL) with its two-digit hex escape (`\5c`, `\2a`, `\28`, `\29`, `\00`). Escaping rather than stripping is deliberate: rejecting or deleting the characters would either reduce functionality for legitimate usernames containing them or, if done incorrectly, still leave a re-interpretable value; hex-escaping preserves the literal value while making it structurally inert to the filter parser, matching the standard's own escaping mechanism. The `/` character is also escaped as a defense-in-depth measure against some LDAP gateway implementations that treat it specially, though it is not part of the core RFC 4515 reserved set.

The forward slash of the filter's static structure (`(uid=...)`) is untouched, so only the attacker-controlled substring is neutralized — the fix is scoped to the taint source and does not alter the intended query shape. Attributes returned (`uid`, `cn`, `mail`) are unrelated to this injection point and are left as-is.

To verify: send a request with `username` set to a value containing `)`, `(`, or `*` (e.g. `*)(|(uid=*`) and confirm the resulting filter sent to the LDAP server contains the hex-escaped sequence rather than raw metacharacters, and that the search returns only the entry for the literal (escaped) username rather than the broadened result set the unescaped payload would have produced.
