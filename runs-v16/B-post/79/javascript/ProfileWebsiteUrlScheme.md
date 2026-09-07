## Verdict
CONFIRMED - XSS via unvalidated URL scheme in href attribute.

## Source
`profile.websiteUrl` parameter (user-controlled input) from line 14.

## Fix

**Vulnerable code:**
```javascript
function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  const websiteUrl = escapeAttribute(profile.websiteUrl || '#'); // Problem: escapeAttribute does not validate URL schemes

  return `<a class="profile-link" href="${websiteUrl}" rel="nofollow">${displayName}</a>`;
}
```

**Fixed code:**
```javascript
function isValidUrl(urlString) {
  // '#' is allowed as a safe default fallback
  if (urlString === '#') {
    return true;
  }
  
  try {
    const parsed = new URL(urlString);
    // Allowlist of safe protocols only
    const allowedProtocols = ['https:', 'http:', 'mailto:'];
    return allowedProtocols.includes(parsed.protocol);
  } catch {
    // Invalid URL format, treat as unsafe
    return false;
  }
}

function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  let websiteUrl = profile.websiteUrl || '#';
  
  // Validate URL scheme before using in href
  if (!isValidUrl(websiteUrl)) {
    websiteUrl = '#'; // Fall back to safe default
  }

  return `<a class="profile-link" href="${websiteUrl}" rel="nofollow">${displayName}</a>`;
}
```

## Explanation
The original code applied HTML entity escaping to the URL, which prevents breakout from the attribute but does not prevent dangerous URL schemes. Attackers can inject `javascript:`, `data:text/html`, or other executable schemes that browsers interpret as code when the link is clicked. The fix adds protocol validation using `new URL()` to parse the URL and check that its scheme is in an allowlist (`https:`, `http:`, `mailto:`). Invalid URLs or those with dangerous schemes fall back to `'#'`, a safe inert anchor that matches the original code's fallback behavior. The `URL` constructor is part of the JavaScript standard library (Web API in browsers, Node.js built-in since v10).

## Behaviour changes
- Malicious URLs with schemes like `javascript:`, `data:`, `vbscript:`, etc. are rejected and replaced with `'#'` instead of being rendered.
- Valid URLs with `http://`, `https://`, or `mailto:` schemes render normally.
- The default fallback behavior (using `'#'` for missing or invalid URLs) is preserved.
- Users clicking a link that was rewritten to `'#'` navigate to the current page anchor instead of executing a script.
