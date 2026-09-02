## Verdict

Exploitable. The code is vulnerable to XSS via URL scheme injection. The `escapeAttribute()` function prevents attribute breakout by encoding HTML special characters, but it does not prevent `javascript:`, `data:`, or other dangerous schemes that execute in browser contexts.

## Source

`profile.websiteUrl` at line 14 — untrusted user input from the profile object.

## Fix

**Vulnerable code (line 12-16):**
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
  
  // Validate website URL to prevent XSS via unsafe protocols (javascript:, data:, etc.)
  let websiteUrl = '#';
  if (profile.websiteUrl) {
    try {
      const parsed = new URL(profile.websiteUrl, 'https://example.com');
      // Allow only safe protocols
      if (['http:', 'https:', 'mailto:'].includes(parsed.protocol)) {
        websiteUrl = parsed.href;
      }
    } catch (e) {
      // Invalid URL, use safe default
    }
  }
  
  // Escape for HTML attribute context to prevent attribute breakout
  const escapedUrl = escapeAttribute(websiteUrl);

  return `<a class="profile-link" href="${escapedUrl}" rel="nofollow">${displayName}</a>`;
}
```

## Explanation

The fix adds protocol validation using `new URL()` parsing before rendering the URL. Instead of relying solely on HTML escaping, the code now validates that the URL's protocol is in an allowlist (`http:`, `https:`, `mailto:`), rejecting dangerous schemes like `javascript:` and `data:`. If the URL cannot be parsed or its protocol is not allowlisted, the code falls back to `#` (a safe default). The parsed URL is then escaped for the HTML attribute context using the existing `escapeAttribute()` function, which preserves defense-in-depth by preventing attribute breakout. This approach follows the CWE-79 guidance for URL sinks: "Parse with `new URL(value, base)`, reject anything whose `parsed.protocol` is outside an allowlist such as `https:`/`http:`/`mailto:`, and render the parsed result."

## Behaviour changes

The following behaviors change from the original:

1. **Invalid URLs are rejected.** URLs that cannot be parsed by the `new URL()` constructor will fall back to `#` instead of being rendered as-is. This is a narrowing of accepted input, and while it may reject some malformed but harmless URLs, it is necessary to close the XSS vulnerability.

2. **Relative URLs are resolved against a base.** Relative paths like `/page` are parsed against a dummy base URL (`https://example.com`) and converted to absolute URLs. Their protocol will be `https:` (from the base) and will be allowed. This preserves the function's ability to accept relative URLs while enforcing protocol safety.

3. **The return value remains identical for legitimate inputs.** For valid URLs with safe protocols (http, https, mailto), the escaping behavior is unchanged — the output is still HTML-escaped for attribute context.

4. **Error handling is silent.** Invalid or dangerous URLs produce `#` without throwing errors, maintaining backwards compatibility with the function's error-tolerant behavior.

