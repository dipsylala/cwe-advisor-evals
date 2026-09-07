## Verdict
Confirmed CWE-79 (Cross-site Scripting) vulnerability via unsafe protocol handling in URL context.

## Source
Line 16 in profileLinkRenderer.js embeds `websiteUrl` directly into an `href` attribute after HTML escaping. HTML escaping alone is insufficient for URLs because it does not prevent protocol-based XSS attacks such as `javascript:alert('XSS')`, which contain no HTML special characters and execute when clicked.

## Fix

### File: profileLinkRenderer.js
```javascript
'use strict';

function escapeAttribute(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function isUrlSafe(url) {
  if (!url) {
    return true;
  }

  const lowerUrl = String(url).toLowerCase().trim();

  // Block dangerous protocols that can execute scripts
  const dangerousProtocols = ['javascript:', 'data:', 'vbscript:'];
  for (const protocol of dangerousProtocols) {
    if (lowerUrl.startsWith(protocol)) {
      return false;
    }
  }

  return true;
}

function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  let websiteUrl = profile.websiteUrl || '#';

  // Validate URL protocol to prevent XSS attacks
  if (!isUrlSafe(websiteUrl)) {
    websiteUrl = '#';
  }

  const escapedUrl = escapeAttribute(websiteUrl);
  return `<a class="profile-link" href="${escapedUrl}" rel="nofollow">${displayName}</a>`;
}

module.exports = { renderProfileWebsite };
```

## Explanation
The vulnerability exists because HTML-escaping is designed to prevent HTML injection (tag manipulation), not protocol-based XSS in URL contexts. A malicious `websiteUrl` value like `javascript:alert('XSS')` contains no HTML special characters, so `escapeAttribute()` leaves it unchanged. When placed in an `href` attribute, the browser executes the JavaScript protocol when the link is clicked.

The fix adds an `isUrlSafe()` validation function that checks the URL scheme before it is used. This function explicitly blocks dangerous protocols (`javascript:`, `data:`, `vbscript:`) that can execute arbitrary code. If the URL has a dangerous protocol, it is replaced with the safe default value `'#'`. The remaining HTML escaping is preserved as defense-in-depth for any edge cases.

This approach is protocol-agnostic and allows any safe scheme, including relative URLs (starting with `/`), `http://`, `https://`, `mailto:`, and `#`.
