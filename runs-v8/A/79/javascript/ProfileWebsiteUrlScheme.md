## Verdict

Real vulnerability. HTML escaping does not prevent protocol-based XSS via `javascript:` URLs in href attributes.

## Source

`profile.websiteUrl` on line 14-16 flows untrusted user input into the `href` attribute without protocol validation.

## Fix

Validate the URL scheme before rendering:

```javascript
function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  let websiteUrl = profile.websiteUrl || '#';
  
  // Validate URL protocol - only allow http and https
  if (websiteUrl && websiteUrl !== '#') {
    try {
      const url = new URL(websiteUrl);
      if (!['http:', 'https:'].includes(url.protocol)) {
        websiteUrl = '#';
      }
    } catch {
      // Invalid URL format, use safe default
      websiteUrl = '#';
    }
  }
  
  const escapedUrl = escapeAttribute(websiteUrl);
  const displayNameEscaped = escapeAttribute(displayName);
  
  return `<a class="profile-link" href="${escapedUrl}" rel="nofollow">${displayNameEscaped}</a>`;
}
```

## Explanation

The `escapeAttribute()` function only escapes HTML metacharacters and is insufficient for URL attributes. Browsers parse `href` values as URLs and execute the protocol directive (`javascript:`, `data:`, `vbscript:`) regardless of HTML encoding. Protocol validation using the URL constructor ensures only safe schemes (`http` and `https`) are allowed. Invalid or malicious URLs fall back to `#`. The escaped output remains in place to handle HTML special characters within valid URLs.
