## Verdict

Confirmed - exploitable. CWE-79 (Cross-Site Scripting), specifically the `javascript:`/`data:` URL-scheme variant.

## Source

`profile.websiteUrl`, a profile field controlled by the profile's owner (attacker-controlled from the perspective of anyone viewing the profile).

## Fix

### File: profileLinkRenderer.js

```javascript
'use strict';

const ALLOWED_PROTOCOLS = new Set(['https:', 'http:', 'mailto:']);

function escapeAttribute(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sanitizeWebsiteUrl(value) {
  if (!value) {
    return '#';
  }

  let parsed;
  try {
    parsed = new URL(value);
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

`renderProfileWebsite` puts `profile.websiteUrl` into the `href` attribute of an anchor tag after running it through `escapeAttribute`, which only HTML-entity-encodes `& < > " '`. That neutralizes attribute-breakout (e.g. closing the `href` quote to inject a new attribute or tag) but does nothing about the URL's own scheme: a value such as `javascript:alert(document.cookie)` or `data:text/html,<script>...</script>` contains none of the characters `escapeAttribute` touches, passes through unchanged, and lands directly in `href`. A visitor who clicks the rendered link then executes attacker-controlled script in their own session - this is the CWE-79/URL-sink pattern the JavaScript guidance calls out explicitly: percent/entity-encoding "leaves the `javascript:` and `data:text/html` schemes intact and merely encodes their payload."

The fix adds `sanitizeWebsiteUrl`, which parses the value with `new URL(value)` and keeps it only if `parsed.protocol` is on an explicit allowlist (`https:`, `http:`, `mailto:`); anything that fails to parse as an absolute URL or resolves to a disallowed scheme (`javascript:`, `data:`, `vbscript:`, etc.) is replaced with the existing safe fallback `'#'` - the same fallback the code already used for a missing URL. The parsed, allowlisted `href` is then still passed through the existing `escapeAttribute` before being interpolated, so attribute-breakout protection is unchanged and only additive. `displayName` handling and the HTML entity encoder are untouched.

## Behaviour changes

- A `websiteUrl` that is not a well-formed absolute URL (e.g. a bare domain like `example.com` with no scheme, or a relative path like `/me`) now renders as `href="#"` instead of being emitted verbatim. Previously such values were also functionally broken links (browsers resolve a scheme-less `href` as a relative path against the current page), so this is a low-risk tightening, but it is a visible change for any legitimate stored value that lacks an explicit `http(s)://` or `mailto:` scheme.
- Values using schemes other than `https:`, `http:`, or `mailto:` (`javascript:`, `data:`, `vbscript:`, `ftp:`, etc.) now render as `href="#"` instead of the literal value. This is the intended fix - it is exactly what removes the exploitable path - but it does mean any legitimate `ftp:`/`tel:`/custom-scheme website URL a profile might have stored will also fall back to `#` unless added to `ALLOWED_PROTOCOLS`.
- No change to `displayName` handling, to the fallback text `'Member'`, or to the returned markup's structure/attributes.
- Verified with `node --check` (syntax) and a standalone run (outside the case directory, on a scratch copy) confirming: a `javascript:` payload now renders `href="#"`, a `data:text/html` payload now renders `href="#"`, and a legitimate `https://example.com/me` value renders unchanged.
