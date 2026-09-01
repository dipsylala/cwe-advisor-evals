## Verdict
exploitable

## Source
The `data` parameter passed to the `handleSink` method is untrusted input from an external caller, with no validation of whether it represents a safe redirect destination.

## Fix
**Vulnerable code:**
```java
// SAST FINDING: CWE-601 (URL Redirection to Untrusted Site) reported here. Sink is the next statement.
response.sendRedirect(data);
```

**Fixed code:**
```java
URI uri;
try {
    uri = new URI(data);
} catch (URISyntaxException exceptURISyntax) {
    response.getWriter().write("Invalid redirect URL");
    return;
}

// Validate redirect destination: only allow relative paths
// Reject any URL with a host (external/absolute/scheme-relative redirect)
if (uri.getHost() != null || !data.startsWith("/")) {
    response.getWriter().write("Invalid redirect URL");
    return;
}

// Safe to redirect to relative path
response.sendRedirect(data);
```

## Explanation
The vulnerability occurs because the code passes untrusted user input directly to `response.sendRedirect()` without validating that the destination is safe. An attacker can craft a redirect URL pointing to a malicious site (e.g., `https://attacker.com` or the scheme-relative form `//evil.example`), deceiving users into visiting the attacker's site. The fix adds validation using the parsed URI's `getHost()` method to reject any URL with a non-null host component (which indicates an absolute or scheme-relative URL), and also requires relative paths to start with `/`. This ensures only safe, context-relative redirects are permitted, eliminating the open-redirect attack vector.

## Behaviour changes
The fix adds an additional validation step before the redirect occurs. When an invalid redirect URL is provided (one with a host component or not starting with `/`), the code writes an error message and returns instead of performing the redirect. This is a behaviour change from the original code, which would have redirected to any valid URI syntax. The new behaviour is necessary to eliminate the security vulnerability and prevents malicious external redirects while preserving the legitimate functionality of redirecting to relative application paths.
