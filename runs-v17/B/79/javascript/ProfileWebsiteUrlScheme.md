## Verdict

The finding is confirmed. Line 16 uses `websiteUrl` (sourced from untrusted `profile.websiteUrl`) directly in an `href` attribute without URL scheme validation. The `escapeAttribute()` function only escapes HTML entities (`&`, `<`, `>`, `"`, `'`) but does not validate the URL protocol. An attacker can inject URLs with dangerous schemes such as `javascript:`, `data:text/html`, or `vbscript:` that will execute code when the link is clicked.

## Source

**Source:** `profile.websiteUrl` (untrusted input)  
**Sink:** Line 16: `href="${websiteUrl}"` (embedded in HTML href attribute)  
**Data Flow:** `profile.websiteUrl` → `escapeAttribute()` (line 14) → `websiteUrl` → rendered in href attribute (line 16)

**Vulnerability:** The `escapeAttribute()` function escapes HTML special characters but does not validate the URL's protocol. A URL like `javascript:alert('XSS')` contains no special HTML characters, so it passes through unchanged and executes when clicked.

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

function isValidWebsiteUrl(urlString) {
  const url = String(urlString).trim() || '#';
  
  try {
    const parsed = new URL(url);
    return ['http:', 'https:', 'mailto:'].includes(parsed.protocol);
  } catch (e) {
    // Relative URL - check for dangerous schemes
    const lowerUrl = url.toLowerCase();
    return !lowerUrl.startsWith('javascript:') && 
           !lowerUrl.startsWith('data:') &&
           !lowerUrl.startsWith('vbscript:');
  }
}

function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  let websiteUrl = profile.websiteUrl || '#';
  
  // Validate URL scheme to prevent javascript: and data: XSS
  if (!isValidWebsiteUrl(websiteUrl)) {
    websiteUrl = '#';
  }
  
  websiteUrl = escapeAttribute(websiteUrl);

  return `<a class="profile-link" href="${websiteUrl}" rel="nofollow">${displayName}</a>`;
}

module.exports = { renderProfileWebsite };
```

## Explanation

The fix adds URL scheme validation before rendering the `href` attribute. A new helper function `isValidWebsiteUrl()` validates the URL using the Web URL API (`new URL()`), checking that absolute URLs use only safe protocols (`http:`, `https:`, or `mailto:`). For relative URLs (which fail to parse as absolute), the function checks that they do not start with dangerous schemes (`javascript:`, `data:`, `vbscript:`). If validation fails, the URL is replaced with `#`, a safe fallback.

After validation, the URL is still passed through `escapeAttribute()` to safely render it in the HTML attribute context, escaping special characters like quotes that might otherwise break the attribute value.

This approach follows the CWE-79 JavaScript guidance: parse the URL with `new URL()`, reject anything whose protocol is outside an allowlist (`https:`, `http:`, `mailto:`), and reject relative URLs with dangerous scheme prefixes.

## Behaviour changes

**Before:**
- `https://example.com` → rendered as `<a href="https://example.com">...</a>` ✓
- `javascript:alert('XSS')` → rendered as `<a href="javascript:alert('XSS')">...</a>` ✗ (XSS vulnerability)
- `data:text/html,<script>alert('XSS')</script>` → rendered with `data:` scheme ✗ (XSS vulnerability)
- `/relative/path` → rendered as `<a href="/relative/path">...</a>` ✓
- `mailto:user@example.com` → rendered as `<a href="mailto:user@example.com">...</a>` ✓

**After:**
- `https://example.com` → rendered as `<a href="https://example.com">...</a>` ✓
- `javascript:alert('XSS')` → replaced with `#`, rendered as `<a href="#">...</a>` ✓ (attack prevented)
- `data:text/html,<script>alert('XSS')</script>` → replaced with `#`, rendered as `<a href="#">...</a>` ✓ (attack prevented)
- `/relative/path` → rendered as `<a href="/relative/path">...</a>` ✓
- `mailto:user@example.com` → rendered as `<a href="mailto:user@example.com">...</a>` ✓

Legitimate URLs continue to work. Malicious URLs with dangerous schemes are neutralized by replacing them with a safe default (`#`), preventing XSS execution.
