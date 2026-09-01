## Verdict

Exploitable. The function renders an untrusted URL in an `href` attribute without validating the protocol scheme. HTML entity encoding does not prevent protocol-based XSS attacks like `javascript:alert('XSS')`, where the protocol scheme remains intact after encoding.

## Source

`profile.websiteUrl` is untrusted user-supplied data that flows directly to the `href` attribute of an HTML link element without protocol validation. The source is the function parameter and is under attacker control.

## Fix

**Vulnerable code (line 12-17):**
```javascript
function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  const websiteUrl = escapeAttribute(profile.websiteUrl || '#');

  return `<a class="profile-link" href="${websiteUrl}" rel="nofollow">${displayName}</a>`;
}
```

**Fixed code:**
```javascript
function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  let websiteUrl = '#';
  
  if (profile.websiteUrl) {
    try {
      // Parse URL to validate protocol and prevent javascript: / data: XSS
      const base = typeof window !== 'undefined' ? window.location.origin : 'http://localhost';
      const parsed = new URL(profile.websiteUrl, base);
      
      // Only allow safe protocols
      const allowedProtocols = ['http:', 'https:', 'mailto:'];
      if (allowedProtocols.includes(parsed.protocol)) {
        websiteUrl = parsed.href;
      }
    } catch {
      // Invalid URL format, use default '#'
    }
  }
  
  const escapedUrl = escapeAttribute(websiteUrl);
  return `<a class="profile-link" href="${escapedUrl}" rel="nofollow">${displayName}</a>`;
}
```

## Explanation

The original code uses `escapeAttribute()` to HTML-encode the URL before rendering it in the `href` attribute. However, HTML entity encoding is context-specific and does not prevent protocol-based XSS. For example, the payload `javascript:alert('XSS')` becomes `javascript:alert(&#39;XSS&#39;)` after HTML encoding, but the browser still recognizes the `javascript:` protocol scheme and executes the script.

The fix uses `new URL()` to parse and normalize the URL, then validates that the protocol is in a strict allowlist of safe schemes (`http:`, `https:`, `mailto:`). Any URL with a dangerous protocol (like `javascript:`, `data:`, `vbscript:`, etc.) is rejected and the default safe value `#` is used instead. This ensures that only URLs with explicitly approved schemes are rendered in the `href` attribute. The parsed URL is still HTML-escaped before rendering to handle any special characters in the remaining portions of the URL.

## Behaviour changes

1. **Relative URLs converted to absolute:** Relative URLs like `profile/about` are now parsed with a base URL and converted to absolute form (e.g., `http://localhost/profile/about`). This preserves functionality since the browser navigates to the correct target, but changes the rendered HTML representation. The base URL defaults to `window.location.origin` in browser contexts or `http://localhost` in Node.js testing contexts.

2. **Invalid URLs use safe default:** Malformed URLs that cannot be parsed by `new URL()` now use the default value `#` instead of being rendered as-is. This prevents rendering of URLs that might be syntactically invalid or exploitable.

3. **New error handling path:** The function now wraps URL parsing in a try-catch block to gracefully handle invalid URLs. This adds a new control flow path but does not change the return type or contract of the function.
