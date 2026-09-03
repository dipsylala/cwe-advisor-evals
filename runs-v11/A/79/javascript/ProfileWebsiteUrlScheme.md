## Verdict

XSS via dangerous URL scheme. The `escapeAttribute()` function escapes HTML special characters but does not validate the URL scheme. A user-supplied URL with a dangerous scheme like `javascript:alert('xss')` bypasses attribute escaping and executes when clicked.

## Source

Line 16 inserts `websiteUrl` into the href attribute after calling `escapeAttribute()` on line 14. The `escapeAttribute()` function only escapes HTML special characters (&, <, >, ", ') but does not validate that the URL uses a safe scheme. Dangerous schemes like `javascript:`, `data:`, and `vbscript:` pass through unchanged.

## Fix

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

function isSafeUrl(url) {
  try {
    const parsed = new URL(url, 'http://localhost');
    const safeSchemes = ['http:', 'https:', 'mailto:', 'ftp:', 'ftps:'];
    return safeSchemes.includes(parsed.protocol);
  } catch {
    // Relative URLs are safe
    return !url.includes(':') || /^\//.test(url);
  }
}

function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  let websiteUrl = profile.websiteUrl || '#';
  
  // Validate URL scheme before rendering
  if (!isSafeUrl(websiteUrl)) {
    websiteUrl = '#';
  }
  
  const escapedUrl = escapeAttribute(websiteUrl);

  return `<a class="profile-link" href="${escapedUrl}" rel="nofollow">${displayName}</a>`;
}

module.exports = { renderProfileWebsite };
```

## Explanation

Escaping HTML attribute delimiters is insufficient protection for URLs. Dangerous URL schemes like `javascript:`, `data:`, and `vbscript:` do not contain special characters that `escapeAttribute()` targets, so they pass through unfiltered and execute when the link is clicked.

The fix adds URL scheme validation using the URL constructor before rendering. The `isSafeUrl()` function parses the URL and checks that it uses an allowed scheme (http, https, mailto, ftp, ftps). If the URL uses a dangerous scheme or cannot be parsed, it defaults to `#`. Relative URLs are also accepted as safe. This ensures that only URLs with safe schemes reach the href attribute, preventing script execution.

