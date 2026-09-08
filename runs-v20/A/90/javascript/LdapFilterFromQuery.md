## Verdict

Confirmed. `req.query.username` flows unescaped into an LDAP filter string that is passed to `client.search()`, allowing filter-syntax injection (e.g. `*)(uid=*` style tautologies, or extra filter clauses) to alter the query the directory server evaluates.

## Source

`req.query.username` (line 7) — untrusted HTTP query parameter, read directly from the incoming Express request with no validation or encoding before being concatenated into the LDAP filter string.

## Fix

### File: LdapFilterFromQuery.js

```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

// RFC 4515 section 3: escape the characters that are special inside an LDAP
// filter (backslash, asterisk, parentheses, NUL) so attacker-supplied values
// cannot inject extra filter clauses or wildcards.
function escapeLdapFilterValue(value) {
  return String(value).replace(/[\\*()\0]/g, (char) => {
    switch (char) {
      case '\\':
        return '\\5c';
      case '*':
        return '\\2a';
      case '(':
        return '\\28';
      case ')':
        return '\\29';
      case '\0':
        return '\\00';
      default:
        return char;
    }
  });
}

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  if (typeof username !== 'string' || username.length === 0) {
    return res.status(400).json({ error: 'username query parameter is required' });
  }

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

The handler built the LDAP search filter by string-concatenating the raw `username` query parameter into `(uid=...)` and handed it straight to `ldapjs`'s `client.search()`. `ldapjs` does not parse or sanitize the `filter` string when it is passed as a plain string (it is compiled directly into the wire-protocol filter via its internal filter parser), so any RFC 4515 metacharacter in `username` becomes live filter syntax rather than a literal value.

An attacker supplying `*` can turn the equality match into a broad wildcard match, and one supplying `)(...)` can close the intended clause early and append additional filter terms (e.g. `*)(|(uid=*` style constructions), changing which directory entries the search returns or bypassing the intended `uid` scoping entirely — the classic LDAP filter injection pattern, analogous to SQL injection but against the LDAP query grammar.

The fix keeps the same query shape and wire format (no library swap, no behavior change for legitimate input) and instead neutralizes the value before it is embedded: `escapeLdapFilterValue()` backslash-escapes the five characters RFC 4515 defines as special inside a filter — `\`, `*`, `(`, `)`, and NUL — using their two-digit hex escape form (`\5c`, `\2a`, `\28`, `\29`, `\00`). Escaping rather than stripping or allowlisting was chosen deliberately: a username can legitimately contain characters like `*` in some directory conventions, and stripping would silently corrupt the value, while an allowlist regex is a product decision about what usernames are valid, not a security default — escaping preserves the literal value while removing its ability to act as filter syntax. A basic presence/type check on `username` was added since `req.query.username` can otherwise be `undefined` or an array, which would previously reach `ldap.createClient` and fail in a less clear way.

To verify: before the fix, a request with `username=*` returns every entry under `ou=people,dc=example,dc=com` instead of a single matching entry; after the fix, `*` is escaped to `\2a` and the search matches only a literal username of `*` (i.e., no entries, since no such uid exists), while a normal username such as `jdoe` continues to match exactly as before.
