## Verdict

Confirmed. `POST /api/transfer` in `transferRoutes.js` performs a state-changing money transfer gated only by session cookie auth (`requireSession`) and the same-site check in `csrfOriginPolicy.js`. That check, `allowSameOriginOrMissing`, has two bypasses that make it ineffective as CSRF protection:

1. It returns `true` (allow) whenever both the `Origin` and `Referer` headers are absent. A cross-site form POST or an attacker using `fetch`/XHR with `referrerPolicy: 'no-referrer'` can arrive with neither header set, sailing straight through.
2. When a header is present, it compares with `origin.startsWith(expected)` instead of an exact match. `String.prototype.startsWith` only checks a prefix, so an attacker page served from `https://good-bank.com.evil.com` (or `https://good-bank.comevil.com`) produces an `Origin`/`Referer` that starts with `https://good-bank.com` and passes the check even though it is a completely different origin.

Both gaps let a third-party page forge the authenticated transfer request while the browser sends the victim's session cookie, satisfying `requireSession`.

## Source

`req.get('origin')` / `req.get('referer')` in `csrfOriginPolicy.js`, combined with the session cookie read via `req.session.userId` in `transferRoutes.js`. The attacker-controlled inputs are the `Origin`/`Referer` headers (both are omittable or spoofable in intent from a cross-site page) and the request body fields `toAccount` / `amountCents`.

## Fix

### File: csrfOriginPolicy.js

```javascript
'use strict';

function allowSameOriginOrMissing(req) {
  const sourceHeader = req.get('origin') || req.get('referer');

  // No Origin and no Referer on a state-changing request is itself
  // suspicious for a browser-issued request; refuse rather than allow.
  if (!sourceHeader) {
    return false;
  }

  let sourceOrigin;
  try {
    sourceOrigin = new URL(sourceHeader).origin;
  } catch (err) {
    // Unparseable header - fail closed.
    return false;
  }

  const expectedOrigin = `${req.protocol}://${req.get('host')}`;

  // Exact origin comparison. Do not use startsWith()/includes() here -
  // "https://good-bank.com" is a *prefix* of the attacker-controlled
  // origin "https://good-bank.com.evil.com", so a substring/prefix
  // check is bypassable by registering a sibling domain.
  return sourceOrigin === expectedOrigin;
}

module.exports = { allowSameOriginOrMissing };
```

## Explanation

The fix keeps the function's name and signature (`allowSameOriginOrMissing(req)`) so the existing call site in `transferRoutes.js` needs no change, but corrects both defects in its logic:

- **Missing header now fails closed.** A same-origin browser request to a same-origin API endpoint always carries at least one of `Origin` or `Referer` in modern browsers; a request with neither is either a non-browser client that can be given a proper CSRF token flow separately, or a cross-site request whose sender stripped the header specifically to dodge this check. Treating "missing" as "trusted" inverted the security property; it now returns `false` and the route responds `403`.
- **Prefix comparison replaced with exact origin comparison.** `Origin`/`Referer` are parsed with the WHATWG `URL` API and compared via `.origin` (scheme + host + port, normalized) against the server's own `${req.protocol}://${req.get('host')}`, built the same way it already was. This closes the sibling-domain bypass (`good-bank.com.evil.com`) that `startsWith` allowed, because equality requires the entire origin to match, not just a leading substring. A header that fails to parse as a URL is also treated as untrusted and rejected, rather than being passed to `startsWith` where a malformed value could produce a false positive.
- No behavior changed in `transferRoutes.js` or `transferLedger.js`: the route still requires a valid session first, then delegates the CSRF check to the (now-correct) policy function before touching the ledger, so legitimate same-origin transfers still succeed while forged cross-site ones are rejected with `403`.
