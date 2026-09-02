## Verdict

**Exploitable.** CWE-90 (LDAP Injection). Confidence: high.

## Source

`req.query.username` (line 7) - the Express `username` query-string parameter, fully attacker-controlled with no validation or escaping applied before use.

## Fix

Data flow: `req.query.username` (line 7) is concatenated directly into an LDAP filter string at line 11 (`'(uid=' + username + ')'`), and that filter is passed unmodified into `client.search()` (ldapjs) at line 22 - the taint sink. An input such as `*)(objectClass=*` closes the `uid` term early and appends a second clause, and a bare `*` turns the equality test into a wildcard that matches every entry.

Library recommendation: none required. The knowledge base for this CWE/language pair does not name a third-party escaping library, and ldapjs itself does not ship a filter-escaping helper, so the fix implements RFC 4515 escaping directly rather than guessing at a package name.

Vulnerable code (lines 1-11, relevant excerpt):

```javascript
router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  // VULNERABLE: untrusted input concatenated directly into an LDAP filter
  const filter = '(uid=' + username + ')';
  ...
```

Fixed code:

```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

// RFC 4515 filter escaping: replace each special character with its
// backslash + two-digit-hex encoding. Using a single regex/callback pass
// (rather than chained .replace() calls) avoids re-escaping the backslash
// that a sequential replace of '\\' first would otherwise introduce.
function escapeLdapFilterValue(value) {
  return String(value).replace(/[\\*()\0]/g, (char) => {
    switch (char) {
      case '\\': return '\\5c';
      case '*': return '\\2a';
      case '(': return '\\28';
      case ')': return '\\29';
      case '\0': return '\\00';
      default: return char;
    }
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

The fix inserts `escapeLdapFilterValue()` between the untrusted source and the filter-string sink, backslash-encoding the RFC 4515 metacharacters (`*`, `(`, `)`, `\`, NUL) that give the LDAP filter grammar its structure. Because a single regex pass with a replacer callback classifies and substitutes each character once, there is no risk of the inserted `\5c` sequences being re-escaped by a later pass, which a chain of sequential `.replace()` calls would otherwise require careful ordering to avoid. With the value escaped, a payload like `*)(objectClass=*` or a bare `*` is rendered as literal characters inside the `uid` equality term rather than being parsed as filter syntax, so the query can no longer be split into an additional clause or turned into a wildcard match. `/` is intentionally left unescaped since RFC 4515 assigns it no special meaning and escaping it would corrupt legitimate usernames.

## Behaviour changes

None beyond the escaping itself. The base DN, `scope: 'sub'`, the `attributes` allowlist, the `client.search()` call signature, the error-handling branch, and the `searchEntry`/`end` event wiring are all unchanged. For a username containing no LDAP metacharacters, `escapeLdapFilterValue()` returns the value unmodified, so the fix is behaviour-preserving for all legitimate (non-malicious) input; only inputs that previously altered the filter's structure now match literally instead, which is the intended effect of closing the injection.

Assumption: `username` is treated as a single string value, consistent with the original code's implicit assumption (Express yields an array for a repeated query parameter, and `String()` applied to an array reproduces the same comma-joined result the original `+` concatenation already produced, so this is not a behaviour change).
