## Verdict

**Exploitable XSS vulnerability via URL scheme injection.**

The `websiteUrl` parameter is rendered into an `href` attribute without URL scheme validation. HTML entity encoding (`escapeAttribute()`) does not prevent `javascript:` or `data:` URL schemes from executing in the browser.

## Source

`profile.websiteUrl` (untrusted user input from profile data)

## Fix

Validate the URL scheme before rendering. Parse the user-supplied URL with `new URL()`, allowlist safe protocols (`http:`, `https:`, `mailto:`), and reject everything else by falling back to `#`.

```javascript
function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  let websiteUrl = profile.websiteUrl || '#';
  
  // Validate URL scheme to prevent javascript: and data: URLs
  try {
    const parsed = new URL(websiteUrl);
    const allowedProtocols = ['http:', 'https:', 'mailto:'];
    if (allowedProtocols.includes(parsed.protocol)) {
      websiteUrl = parsed.href;
    } else {
      websiteUrl = '#';
    }
  } catch {
    // Invalid URL format, use safe default
    websiteUrl = '#';
  }
  
  const safeUrl = escapeAttribute(websiteUrl);

  return `<a class="profile-link" href="${safeUrl}" rel="nofollow">${displayName}</a>`;
}

module.exports = { renderProfileWebsite };
```

## Explanation

The original code applied HTML entity encoding to `profile.websiteUrl` but this is insufficient for URL attributes. Entity encoding does not prevent URL scheme attacks—`javascript:alert('XSS')` contains no special HTML characters, so `escapeAttribute()` passes it through unchanged. The browser then executes it as a script when the link is clicked.

The fix validates the URL's protocol against an allowlist before rendering. `new URL()` parses and normalizes the string; if the protocol is not in `['http:', 'https:', 'mailto:']`, the value is rejected and replaced with `#`. If parsing fails (malformed URL), the value is also replaced with `#`. The validated URL is then passed through `escapeAttribute()` for HTML attribute encoding, which handles any ampersands in query strings.

## Behaviour changes

**Safe inputs:** `http://example.com`, `https://example.com`, `mailto:user@example.com` are parsed, validated, normalized via `new URL().href`, and rendered.

**Attack inputs:** `javascript:alert('XSS')`, `data:text/html,<img src=x onerror=alert(1)>`, `JaVaScRiPt:void(0)` (case-insensitive) are rejected and replaced with `#`.

**Malformed inputs:** `htp://typo`, `//incomplete` without a protocol are caught by `new URL()` constructor error and replaced with `#`.

**Legitimate links with query parameters:** `http://example.com?foo=1&bar=2` are normalized and entity-encoded correctly in the HTML attribute (`foo=1&amp;bar=2`).
