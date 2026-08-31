## Verdict

Confirmed. The `username` query parameter is concatenated directly into an LDAP search filter string with no escaping, allowing LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) to alter the filter's logic (e.g. `*` for wildcard/blind enumeration, or `)(...)` to inject additional filter clauses such as `*)(uid=*))(|(uid=*`).

## Source

`req.query.username` (Express query parameter) at line 7 — attacker-controlled, untrusted.

## Fix

```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

// RFC 4515 section 3: escape LDAP filter metacharacters before embedding
// user-controlled values in a search filter.
function escapeLdapFilter(value) {
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

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  const filter = '(uid=' + escapeLdapFilter(username) + ')';

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

The vulnerability is classic LDAP filter injection via string concatenation: `'(uid=' + username + ')'` lets any of the five RFC 4515 special characters (`\`, `*`, `(`, `)`, NUL) pass through unmodified into the filter that `client.search` sends to the directory. An attacker supplying `*` turns an exact-match lookup into a wildcard enumeration of every `uid`; supplying `*)(objectClass=*` (or similar) closes the intended `(uid=...)` clause early and appends attacker-chosen filter terms, which can be used to broaden the match, probe for other attributes, or combine with `|`/`&` logic injected elsewhere in the query construction to bypass intended restrictions.

The fix applies RFC 4515's prescribed escaping to the untrusted value before it is embedded in the filter, rather than attempting to strip or reject characters. Each of the five special characters is replaced with its backslash-prefixed two-digit hex escape (`\5c`, `\2a`, `\28`, `\29`, `\00`), which is the encoding LDAP servers are required to interpret literally rather than as filter syntax — so a username of `*` is searched for as the literal string `*`, not as a wildcard, and `)(` sequences can no longer terminate or extend the filter. This mirrors what dedicated escaping helpers (e.g. the `ldap-escape` package, or `ldapjs`'s own filter-construction helpers where available) do internally, so an equivalent externally maintained escaping utility is an acceptable substitute for the inline function as long as it covers the same RFC 4515 character set. The DN portion of the search (`ou=people,dc=example,dc=com`) is a fixed literal here and does not need equivalent DN escaping, but any future code that builds a DN from user input would need RFC 4514 DN escaping, which is a distinct character set from filter escaping and not interchangeable with it.
