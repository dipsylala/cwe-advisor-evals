## Verdict

**Confirmed.** The function renders an unvalidated URL in an href attribute, allowing javascript: and data: protocol injection despite HTML entity escaping.

## Source

Line 16 places `websiteUrl` directly into the href attribute after HTML entity escaping only. The `escapeAttribute()` function prevents breaking out of the attribute but does not validate URL schemes. An attacker providing `javascript:alert('xss')` as `profile.websiteUrl` will have it rendered as `href="javascript:alert('xss')"`, which executes when clicked.

## Fix

Validate the URL scheme before rendering. Allow only http://, https://, relative paths (/, ./), and fragments (#). Reject any other scheme including javascript:, data:, and bare domain names without a protocol.

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

function isValidUrl(url) {
  if (!url || typeof url !== 'string') {
    return false;
  }
  
  const trimmed = url.trim();
  // Allow http, https, relative paths, and fragments; reject javascript:, data:, etc.
  return /^(?:https?:\/\/|\/|\.\/|#)/.test(trimmed);
}

function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  let websiteUrl = profile.websiteUrl || '#';
  
  // Validate URL scheme to prevent javascript: and data: protocol injection
  if (!isValidUrl(websiteUrl)) {
    websiteUrl = '#';
  }
  
  const escapedUrl = escapeAttribute(websiteUrl);
  return `<a class="profile-link" href="${escapedUrl}" rel="nofollow">${displayName}</a>`;
}

module.exports = { renderProfileWebsite };
```

## Explanation

HTML entity escaping alone is insufficient for URL attributes because it only prevents breaking out of the attribute syntax—it does not restrict the interpretation of dangerous URL schemes. The fix adds a URL scheme validation that whitelists safe protocols (http://, https://) and relative/local references (/, ./, #), then replaces any other URL with a safe fallback (#). This ensures that URLs from untrusted sources cannot execute JavaScript or embed data when rendered in an href attribute.
