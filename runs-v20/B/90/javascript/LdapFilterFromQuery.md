## Verdict

Exploitable. CWE-90 (LDAP Injection). Confidence: high.

## Source

`req.query.username` (Express query-string parameter, line 7) - fully attacker-controlled, no validation or escaping applied before use.

Data flow: `username` is read from the query string, then concatenated directly into an LDAP filter string on line 11 (`'(uid=' + username + ')'`), which is assigned to `opts.filter` and passed to the sink `client.search('ou=people,dc=example,dc=com', opts, ...)` on line 22. An attacker can submit a value such as `*)(uid=*` or `admin)(|(objectClass=*` to alter the filter's logical structure - closing the `uid` clause early and injecting additional filter terms - causing the directory to return entries the query did not intend to match, or every entry in the search base.

## Fix

### File: LdapFilterFromQuery.js

```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  const filter = new ldap.EqualityFilter({ attribute: 'uid', value: username });

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

The vulnerable code built the LDAP filter by string concatenation, so any `*`, `(`, `)`, or `\` in `username` was interpreted as filter syntax by the directory server rather than as literal data. The fix replaces the concatenated string with `ldapjs`'s `EqualityFilter` object (`new ldap.EqualityFilter({ attribute: 'uid', value: username })`), which is passed directly as `opts.filter` in place of the string. `ldapjs` serializes the filter object's `value` through its own RFC 4515 escaping when it builds the wire-format search request, so any metacharacter in `username` is rendered as its escaped hex form (e.g. `*` becomes `\2a`) and can no longer close the `uid` clause or open a new one. The attribute name (`uid`) stays a fixed, code-owned literal, so no allowlist is needed there; `username` is the only tainted value and it now flows through the library's escaping rather than into raw filter text. `ldapjs` already exports `EqualityFilter` as a top-level property of the module already required on line 2, so no new import or dependency was added.

## Behaviour changes

- The `filter` value passed in `opts` changes from a raw string to an `EqualityFilter` object. `ldapjs`'s `client.search()` accepts either form and serializes both to the identical wire-format LDAP filter for a benign `username` (e.g. `username=jdoe` produces `(uid=jdoe)` either way) - this is a construction-mechanism change only, not an observable behaviour change for legitimate input.
- For input containing LDAP metacharacters, the semantic query result changes: characters that previously altered the filter's logical structure (or matched via wildcard) are now matched as literal characters in the `uid` value, so such a search now correctly returns no match instead of an attacker-influenced result set. This is the intended effect of the fix, not a regression.
- Search base (`ou=people,dc=example,dc=com`), `scope`, `attributes`, error handling, and response shape are all unchanged.
- Verification: `node --check` against the fixed file (copied to a scratch location) returned no syntax errors. `EqualityFilter` is named explicitly in the loaded `cwe/90/javascript/INDEX.md` guidance as a member of the `ldapjs` filter-class API (`new ldap.EqualityFilter({ attribute, value })`); it was not independently confirmed against an installed `ldapjs` package since no `package.json`/`node_modules` exists in the case directory - recorded as an assumption resting on the knowledge-base guidance rather than on a local dependency check.
