## Verdict

Exploitable. `req.query.username` (Express query-string parameter, attacker-controlled) reaches `client.search()` (ldapjs) at line 22 as an LDAP filter string built by direct concatenation, with no escaping or validation anywhere on the path.

## Source

- **Source**: `req.query.username` (`LdapFilterFromQuery.js:7`) - untrusted HTTP query parameter, read directly with no validation.
- **Flow**: `username` -> `filter = '(uid=' + username + ')'` (`LdapFilterFromQuery.js:11`) -> `opts.filter` (`LdapFilterFromQuery.js:13-14`) -> `client.search('ou=people,dc=example,dc=com', opts, ...)` (`LdapFilterFromQuery.js:22`).
- **Sink**: `client.search()` (ldapjs). It takes the base DN, an options object (whose `filter` is parsed into an LDAP expression tree), and a callback receiving `(err, search)`; on success it emits `searchEntry`/`end` events consumed at lines 28-32. `scope: 'sub'` and the fixed `attributes` list are untouched by this fix. Failure behaviour (the `err` branch, lines 23-26) is unchanged.

A raw `(`, `)`, or `*` in `username` is not neutralized before reaching the filter, so an attacker can close the `uid` term and inject additional filter clauses, or supply a bare `*` to turn the equality test into a match-everything wildcard against the `ou=people,dc=example,dc=com` subtree.

## Fix

Vulnerable code (`LdapFilterFromQuery.js:7-22`):

```javascript
router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  // VULNERABLE: untrusted input concatenated directly into the LDAP filter
  const filter = '(uid=' + username + ')';

  const opts = {
    filter,
    scope: 'sub',
    attributes: ['uid', 'cn', 'mail'],
  };
```

Fixed code:

```javascript
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

  // FIXED: RFC 4515 filter-value escaping before interpolation
  const filter = '(uid=' + escapeLdapFilterValue(username) + ')';

  const opts = {
    filter,
    scope: 'sub',
    attributes: ['uid', 'cn', 'mail'],
  };
```

No third-party library is named for this fix: the knowledge base's JavaScript guidance for CWE-90 recommends LDAP filter builders or RFC 4515 escaping generically but does not name a specific npm package or version to check, so the fix is a self-contained escaping function rather than a dependency change.

## Explanation

`escapeLdapFilterValue()` replaces the five characters RFC 4515 gives special meaning to in an LDAP filter - backslash, `*`, `(`, `)`, and NUL - with their backslash-prefixed two-digit hex codes, in a single regex pass so the substitution characters it inserts (which themselves contain a backslash) are never re-scanned and re-escaped. Applying it to `username` before concatenation means any `(`, `)`, or `*` in the input is rendered as literal filter-value text instead of being parsed as filter syntax, so it can no longer close the `uid` term, open a new clause, or turn the lookup into a wildcard match. The base DN, search scope, attribute list, and the callback's success/error handling are all unchanged - only the value substituted into the filter is different.

## Behaviour changes

None to the sink's contract or the route's observable behaviour for any username that does not contain `\`, `*`, `(`, `)`, or NUL - those pass through `escapeLdapFilterValue()` unchanged. For a username that does contain one of those characters, the query now searches for that character as literal text in the `uid` attribute (almost certainly matching no entry, since `uid` values don't normally contain them) rather than having the character alter the filter's structure; this is the intended effect of the fix, not an incidental change. `opts.scope`, `opts.attributes`, the base DN, and the `err`/`searchEntry`/`end` handling are all untouched.
