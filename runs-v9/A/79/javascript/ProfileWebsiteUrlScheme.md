## Verdict

Confirmed. `renderProfileWebsite` builds an `href` attribute from `profile.websiteUrl` using only HTML-entity escaping. Entity escaping neutralizes `<`, `>`, `"`, `'`, and `&`, but it does not restrict which URL scheme ends up in the attribute. A profile value such as `javascript:alert(document.cookie)` contains none of the escaped characters, so it passes through `escapeAttribute` unchanged and is emitted verbatim as the anchor's `href`. When a user clicks the rendered link, the browser executes the `javascript:` URL in the page's origin, giving stored/reflected XSS despite the existing escaping.

## Source

`profile.websiteUrl` (line 14, flowing into the template literal at line 16) — attacker-controlled profile data (e.g. a user-editable "website" field) reaching an HTML `href` sink with no scheme validation.

## Fix

```js
'use strict';

function escapeAttribute(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

function sanitizeWebsiteUrl(rawUrl) {
  if (!rawUrl) {
    return '#';
  }

  try {
    // A base is supplied so protocol-relative/relative inputs resolve
    // predictably instead of throwing; the scheme check below still
    // rejects anything that isn't absolute http(s).
    const parsed = new URL(String(rawUrl), 'https://example.invalid');
    if (ALLOWED_PROTOCOLS.has(parsed.protocol)) {
      return parsed.href;
    }
  } catch {
    // Falls through to '#' below.
  }

  return '#';
}

function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  const websiteUrl = escapeAttribute(sanitizeWebsiteUrl(profile.websiteUrl));

  return `<a class="profile-link" href="${websiteUrl}" rel="nofollow">${displayName}</a>`;
}

module.exports = { renderProfileWebsite };
```

## Explanation

HTML-entity escaping and URL-scheme validation address two different attacks and neither substitutes for the other: entity escaping stops the value from breaking out of the `href="..."` attribute (e.g. closing the quote to inject new attributes or markup), while scheme validation stops the value itself from being a dangerous protocol handler. `escapeAttribute` alone leaves `javascript:`, `data:`, `vbscript:`, and similar schemes fully intact, so they render as click-triggered script execution even though the markup is well-formed.

The fix adds `sanitizeWebsiteUrl`, which parses the profile-supplied URL with the `URL` constructor and only accepts it if `parsed.protocol` is `http:` or `https:` (an allowlist, not a denylist — new dangerous schemes don't require future updates here). Anything else, including `javascript:`, malformed input, or relative paths that resolve to a disallowed scheme, falls back to the existing safe default of `#`. The sanitized, now-guaranteed-benign URL is then still passed through `escapeAttribute` before being interpolated, so both the scheme-injection and attribute-breakout classes of attack are closed together, and legitimate `http`/`https` website links continue to render normally.
