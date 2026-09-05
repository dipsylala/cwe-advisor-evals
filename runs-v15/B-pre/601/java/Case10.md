## Verdict

Exploitable. Untrusted input from an external URL reaches `response.sendRedirect()` without adequate validation. URI syntax validation does not prevent open redirects to arbitrary external domains.

## Source

Case10A line 38: `data = readerBuffered.readLine()` reads a line from external URL `http://www.example.org/`. This untrusted string is passed to Case10B.handleSink() as the `data` parameter, which reaches the sink at Case10B line 32.

## Fix

Replace the URI syntax-only validation with host and scheme validation. Reject any URI that has a non-null host (absolute URLs including protocol-relative like `//evil.com`) or a non-null scheme (including `javascript:`, `data:`, etc.). Only allow relative paths, which have both host and scheme as null.

```java
URI uri;
try
{
    uri = new URI(data);
}
catch (URISyntaxException exceptURISyntax)
{
    response.getWriter().write("Invalid redirect URL");
    return;
}

// Reject absolute URLs (non-null host) and absolute URIs with null host (javascript:, data:, etc.)
// Only relative paths (no host, no scheme) are safe
if (uri.getHost() != null || uri.getScheme() != null) {
    response.getWriter().write("Invalid redirect URL");
    return;
}

response.sendRedirect(data);
```

## Explanation

The original code validated only URI syntax. A valid URI can still be exploited: `//evil.com` parses successfully with `getHost()="evil.com"`, `javascript:alert(1)` parses with `getScheme()="javascript"`, and absolute external URLs parse with both values set. By checking both `uri.getHost()` and `uri.getScheme()` after parsing, the fix enforces that only relative paths (both null) reach sendRedirect(). Relative paths are safe because the browser resolves them within the application's origin, preventing external redirects. This follows the Java CWE-601 guidance: "Decide on the parsed URI, not the string, but branch on `getHost()`, not `isAbsolute()`: a scheme-relative value like `//evil.example` is not absolute (no scheme) yet has a non-null host."

## Behaviour changes

- **Before**: External URLs and dangerous schemes passed through to sendRedirect() if they were syntactically valid URIs. Attackers could craft payloads like `https://attacker.com` or `//evil.com` that would redirect users.
- **After**: Any redirect target with an absolute URL or dangerous scheme is rejected with an error message. Only relative paths like `/dashboard` or `/path?query=value` are accepted. This eliminates the open redirect while preserving legitimate relative-path redirects within the application.
