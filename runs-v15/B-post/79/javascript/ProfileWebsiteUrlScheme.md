## Verdict

Real - Exploitable.

## Source

Line 16, in the template string: `href="${websiteUrl}"` receives untrusted `profile.websiteUrl` after HTML entity escaping. The `escapeAttribute()` function escapes `&`, `<`, `>`, `"`, and `'`, but does not validate URL schemes. Input like `javascript:alert('XSS')` contains no HTML special characters and passes through unchanged, reaching the `href` attribute where the browser treats it as executable code.

## Fix

Add URL scheme validation before rendering. Only allow `http:`, `https:`, and `mailto:` schemes; relative URLs are safe. Replace dangerous schemes with the safe default (`#`).

```javascript
function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  let urlInput = profile.websiteUrl || '#';
  
  // Validate URL to prevent javascript: and data: URI XSS
  if (urlInput.includes('://')) {
    try {
      const parsed = new URL(urlInput);
      // Only allow safe protocols
      if (!['http:', 'https:', 'mailto:'].includes(parsed.protocol)) {
        urlInput = '#';
      }
    } catch {
      // Invalid URL with scheme, use safe default
      urlInput = '#';
    }
  }
  
  const websiteUrl = escapeAttribute(urlInput);

  return `<a class="profile-link" href="${websiteUrl}" rel="nofollow">${displayName}</a>`;
}
```

## Explanation

HTML entity escaping (`&` → `&amp;`, etc.) protects against XSS in HTML body text and attributes where the browser treats content as text. However, the `href` attribute is parsed as a URL first, and dangerous schemes like `javascript:` and `data:` are executable regardless of HTML encoding because they contain no characters that HTML encoding affects.

The fix validates the URL scheme before rendering. If the URL contains an explicit scheme (detected by `://`), it is parsed and its protocol is checked against an allowlist of safe schemes. Protocols outside the allowlist (`javascript:`, `data:`, etc.) are rejected and replaced with `#`. Relative URLs (starting with `/`, `#`, `?`, or containing no scheme) are permitted because they cannot carry dangerous protocols.

The HTML escaping is retained for safety in case the URL contains encoded characters that need attribute context protection.

## Behaviour changes

**Changed**: URLs with unsafe schemes (`javascript:`, `data:text/html`, `vbscript:`, etc.) are now replaced with `#` and will not navigate or execute code when clicked.

**Unchanged**: Valid `http://` and `https://` URLs work as before. The `mailto:` scheme works as before. Relative URLs like `/profile`, `#section`, and `?query` work as before. The default `#` behavior for missing URLs is preserved. HTML display of the link text remains the same.

**Introduced names**: `new URL()` constructor (ECMAScript built-in).
