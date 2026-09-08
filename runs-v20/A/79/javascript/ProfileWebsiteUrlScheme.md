## Verdict

Confirmed. `renderProfileWebsite` places `profile.websiteUrl` into the `href` attribute of an anchor tag after only HTML-entity-escaping it. HTML-entity escaping neutralizes markup breakout (`"`, `<`, `>`, `'`) but does not neutralize the URL scheme itself. A value such as `javascript:alert(document.cookie)` contains none of the escaped characters, so it passes through `escapeAttribute` unchanged and is emitted verbatim as `href="javascript:alert(document.cookie)"`. When a user clicks the rendered profile link, the browser executes the attacker-controlled script in the victim's session instead of navigating to a site. This is a DOM/stored XSS via dangerous URL scheme, not a markup-injection issue, so attribute escaping alone cannot fix it.

## Source

`profile.websiteUrl`, consumed in `renderProfileWebsite` at `profileLinkRenderer.js` line 14 (read) and rendered into the `href` attribute at line 16 (sink). The value is attacker-controlled profile data (e.g. a user-editable "website" field) with no scheme restriction applied before it reaches the anchor tag.

## Fix

### File: profileLinkRenderer.js

```javascript
'use strict';

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

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

  let parsed;
  try {
    // Resolve against a fixed dummy base so relative-looking inputs
    // (which are not a scheme-injection vector) still validate cleanly,
    // while absolute inputs are checked against their own scheme.
    parsed = new URL(rawUrl, 'https://dummy-base.invalid');
  } catch (err) {
    return '#';
  }

  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    return '#';
  }

  return parsed.href;
}

function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  const websiteUrl = escapeAttribute(sanitizeWebsiteUrl(profile.websiteUrl));

  return `<a class="profile-link" href="${websiteUrl}" rel="nofollow">${displayName}</a>`;
}

module.exports = { renderProfileWebsite };
```

## Explanation

The fix adds `sanitizeWebsiteUrl`, which parses the raw URL with the WHATWG `URL` API and checks the resulting `protocol` against an explicit allowlist of `http:` and `https:` before the value is ever handed to `escapeAttribute`. Any value whose scheme is not in the allowlist - `javascript:`, `data:`, `vbscript:`, or a malformed string that fails to parse - is replaced with the existing safe placeholder `#`, matching the fallback the code already used for a missing URL. A relative-looking value that carries no scheme (e.g. `example.com/profile`) is resolved against a fixed dummy base purely to run it through the same parser; only the resulting protocol is checked, so it is not treated as suspicious on that basis alone.

This preserves the original two-stage design (validate the value's meaning, then HTML-escape it for the attribute context) rather than replacing it: `escapeAttribute` still runs on the sanitized result to close the markup-breakout vector (quotes, angle brackets), while the new scheme check closes the URL-based script-execution vector that escaping alone cannot address. Using the `URL` constructor rather than a regex on the string avoids the common bypass patterns around whitespace, encoded colons, or case variation in the scheme name, since the browser-standard parser normalizes the protocol before comparison.
