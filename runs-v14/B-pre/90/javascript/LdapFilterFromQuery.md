## Verdict

Exploitable. The `username` parameter from `req.query.username` is concatenated directly into an LDAP filter string without escaping or validation, allowing an attacker to inject LDAP metacharacters and modify query logic.

## Source

```javascript
const username = req.query.username;
```

Untrusted user input from the URL query parameter `username`.

## Fix

**Vulnerable Code:**

```javascript
const express = require('express');
const ldap = require('ldapjs');

const router = express.Router();

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  const filter = '(uid=' + username + ')';  // VULNERABLE: direct concatenation without escaping

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

**Fixed Code:**

```javascript
const express = require('express');
const ldap = require('ldapjs');
const { filterEscape } = require('ldapjs-escape');

const router = express.Router();

router.get('/directory/lookup', (req, res) => {
  const username = req.query.username;

  // Validate that username is a non-empty string
  if (!username || typeof username !== 'string' || username.trim() === '') {
    return res.status(400).json({ error: 'username parameter is required and must be non-empty' });
  }

  const client = ldap.createClient({ url: 'ldap://directory.internal:389' });

  // Apply RFC4515 escaping to prevent LDAP injection
  const escapedUsername = filterEscape(username);
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

The fix adds three components: (1) import the `ldapjs-escape` library's `filterEscape` function, which applies RFC4515 escaping to neutralize LDAP special characters (`*`, `(`, `)`, `\`, NUL); (2) apply `filterEscape()` to the untrusted `username` parameter before concatenating it into the filter string, converting injected metacharacters into literal escaped sequences the LDAP parser treats as data rather than syntax; (3) validate that the username parameter is present and non-empty before processing, rejecting requests that lack it with a 400 error. These changes eliminate the LDAP injection vulnerability by ensuring user input cannot modify filter structure. The escaping function handles the complete set of RFC4515 metacharacters in the correct order (backslash first) to prevent double-escaping.

## Behaviour changes

**Input validation added:** A check for non-empty, string-typed username is added, returning a 400 error if validation fails. This is a behaviour change that rejects previously-accepted empty or missing username values. Reason: prevents malformed requests from reaching the LDAP query and improves error handling clarity.

**Library dependency added:** `ldapjs-escape` is introduced as a new dependency. Reason: provides RFC4515-compliant filter escaping and is the standard library for this purpose in Node.js LDAP workflows.

**No changes to search results, error handling contract, or response format.** The filter construction is the only modification; the rest of the search flow, including the callback chain, error responses, and entry collection, remains unchanged.
