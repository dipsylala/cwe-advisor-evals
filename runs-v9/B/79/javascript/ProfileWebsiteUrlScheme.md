## Verdict

exploitable (confidence: high)

- **cwe_id**: CWE-79
- **location**: `profileLinkRenderer.js`, line 16 (the `href="${websiteUrl}"` sink inside `renderProfileWebsite`)

## Source

`profile.websiteUrl`, a user-controlled profile field, passed into `renderProfileWebsite(profile)` at line 14 and run through `escapeAttribute()` before being interpolated into the anchor's `href` attribute at line 16.

`escapeAttribute()` only HTML-entity-encodes `& < > " '`. A `javascript:` URI such as `javascript:alert(document.cookie)` contains none of those characters, so it passes through unchanged and is emitted verbatim as the `href` value. Because the sink is a URL attribute, not an HTML-body or quoted-attribute breakout, entity encoding does nothing to neutralize it — the browser executes the scheme when the link is clicked. This is the `javascript:`/`data:` URL-scheme gap called out explicitly in the JavaScript CWE-79 guidance's `href`/`src` bullet: percent- or entity-encoding leaves the dangerous scheme intact and only encodes its payload.

## Fix

Vulnerable code (`profileLinkRenderer.js`, lines 12-17):

```js
function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  const websiteUrl = escapeAttribute(profile.websiteUrl || '#'); // scheme not validated: javascript:/data: pass straight through

  return `<a class="profile-link" href="${websiteUrl}" rel="nofollow">${displayName}</a>`;
}
```

Fixed code:

```js
'use strict';

const ALLOWED_WEBSITE_PROTOCOLS = new Set(['http:', 'https:']);

function escapeAttribute(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sanitizeWebsiteUrl(rawUrl) {
  if (!rawUrl) {
    return '#';
  }
  try {
    const parsed = new URL(rawUrl);
    if (!ALLOWED_WEBSITE_PROTOCOLS.has(parsed.protocol)) {
      return '#';
    }
    return parsed.href;
  } catch {
    return '#';
  }
}

function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  const websiteUrl = escapeAttribute(sanitizeWebsiteUrl(profile.websiteUrl));

  return `<a class="profile-link" href="${websiteUrl}" rel="nofollow">${displayName}</a>`;
}

module.exports = { renderProfileWebsite };
```

## Explanation

The fix adds `sanitizeWebsiteUrl()`, which parses `profile.websiteUrl` with `new URL()` and allowlists only the `http:` and `https:` protocols before the value is ever handed to `escapeAttribute()`. A `javascript:`, `data:`, `vbscript:`, or any other non-allowlisted scheme fails the protocol check and is replaced with the same `'#'` fallback the code already used for a missing URL, so the link renders as inert rather than executable. Malformed input that `new URL()` cannot parse is caught and falls back the same way. `escapeAttribute()` is kept in place afterward and still does its original job of entity-encoding the value for safe attribute-quote placement — it was never wrong for that purpose, it just wasn't a scheme control, which the new allowlist step now supplies. Per the allowlist-fix-point guidance, the code uses `parsed.href` (the canonical, re-serialized value selected by the check) downstream rather than continuing to pass the original raw string.

## Behaviour changes

- A `websiteUrl` using a non-`http(s)` scheme (`javascript:`, `data:`, `vbscript:`, `file:`, etc.) now renders as `href="#"` instead of being emitted verbatim. This is the intended effect of closing the weakness, not a side effect.
- A `websiteUrl` value that `new URL()` cannot parse as an absolute URL — including a scheme-relative or path-relative value such as `example.com` or `/profile` with no `http(s)://` prefix — now also falls back to `href="#"`, whereas previously such a string was emitted as-is (already an unusable relative fragment relative to nothing, but not previously normalized or rejected). If the application intends to accept bare-domain input for this field, that normalization (e.g. prefixing `https://`) should happen at the point the profile value is validated/stored, not silently reintroduced in this renderer.
- The rendered URL is now the canonical, re-serialized form (`parsed.href`) rather than the original raw string, e.g. `https://Example.com/./a` may render as `https://example.com/a`. This is a byproduct of routing the value through `new URL()` for the protocol check and is not expected to change link destination for well-formed input.
- No change to the `displayName` handling, the surrounding markup, or the `'#'` fallback already used for an absent URL.

**Assumptions**: `websiteUrl` is treated as an absolute, user-supplied link intended for `http`/`https` destinations only (consistent with a profile "website" field); `mailto:` was not added to the allowlist since this field is a website URL, not a contact link. If the product intends to also accept `mailto:` links here, that scheme can be added to `ALLOWED_WEBSITE_PROTOCOLS`.
