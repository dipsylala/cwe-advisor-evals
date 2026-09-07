## Verdict
exploitable

## Source
String data received from untrusted input (passed to handleSink() method, representing an HTTP request parameter in real usage).

## Sink
`response.sendRedirect(data)` at line 32 in Case19B.java.

## Fix

**Vulnerable code:**
```java
if (data != null)
{
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
    
    // SAST FINDING: CWE-601 (URL Redirection to Untrusted Site) reported here. Sink is the next statement.
    response.sendRedirect(data);
    return;
}
```

**Fixed code:**
```java
if (data != null)
{
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
    
    // Validate redirect destination to local paths only
    // Reject external domains (indicated by non-null host)
    if (uri.getHost() != null)
    {
        response.getWriter().write("Redirect to external URLs not allowed");
        return;
    }
    
    // Reject opaque URIs with dangerous schemes (e.g., javascript:, data:)
    if (uri.isAbsolute() && uri.getHost() == null)
    {
        response.getWriter().write("Invalid redirect scheme");
        return;
    }
    
    response.sendRedirect(data);
    return;
}
```

## Explanation
The original code validated that the input is a syntactically valid URI but did not validate that the redirect destination is safe. An attacker could supply a malicious absolute URI (e.g., `https://attacker.com`) that passes URI syntax validation but redirects to an external site. The fix adds two checks after URI parsing: first, it rejects any URI with a non-null host (via `getHost()`), which covers both absolute external URLs and scheme-relative URLs like `//evil.example`. Second, it rejects opaque URIs with null hosts that are absolute (like `javascript:` or `data:`), which can execute code in the browser. Relative paths like `/dashboard` have null hosts and are not absolute, so they pass through safely. This ensures only local redirects are permitted, preventing phishing attacks.

## Behaviour changes
The fix adds two new validation branches that can reject the redirect with error messages:
- If the URI has a host component (indicating an external URL), it now returns an error message instead of redirecting.
- If the URI has an absolute scheme but no host (like `javascript:`), it now returns an error message instead of redirecting.
These changes close the CWE-601 vulnerability by preventing untrusted input from directing users to external sites. The response writer now sends error messages instead of redirect responses for invalid URLs, which is a safe departure from the original behavior that unconditionally redirected any syntactically valid URI.
