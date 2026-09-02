## Verdict

Exploitable. An attacker controlling the external source (http://www.example.org/) can inject an arbitrary URL into the redirect, allowing phishing attacks or credential theft.

## Source

**Case10A.java, line 38:** The untrusted data originates from reading a line from an external URL via `readerBuffered.readLine()`. This data flows to Case10B.handleSink() at line 73.

**Case10B.java, line 32:** The sink is `response.sendRedirect(data)`, where untrusted data from the external source is passed directly without sufficient validation.

## Fix

**Vulnerable code (Case10B.java, lines 14-36):**
```java
public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
{
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
}
```

**Fixed code:**
```java
public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
{
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
        
        // Validate redirect destination is safe
        // Reject external URLs (non-null host) and scheme-relative URLs (//evil.com)
        if (uri.getHost() != null)
        {
            response.getWriter().write("External redirects are not allowed");
            return;
        }
        
        // Reject unsafe URI schemes (javascript:, data:, etc.)
        String scheme = uri.getScheme();
        if (scheme != null && (scheme.equals("javascript") || scheme.equals("data")))
        {
            response.getWriter().write("Unsafe URI scheme");
            return;
        }
        
        // Ensure redirect is a relative path starting with /
        if (!data.startsWith("/"))
        {
            response.getWriter().write("Only relative redirects are allowed");
            return;
        }
        
        response.sendRedirect(data);
        return;
    }
}
```

## Explanation

The vulnerability is introduced because Case10B validates only that the input is a syntactically valid URI but does not verify it is a safe redirect destination. An attacker controlling the external data source can supply any URL, including those pointing to phishing sites or malware.

The fix applies the CWE-601 Java remediation guidance by rejecting external redirects: it checks that the parsed URI has no host (which catches both absolute external URLs and scheme-relative URLs like `//evil.com`), blocks dangerous schemes explicitly, and enforces that only relative paths starting with `/` are permitted. These checks ensure that `sendRedirect()` can only navigate within the application's own domain.

## Behaviour changes

- **Rejected URLs:** The method now rejects and returns an error message instead of redirecting for: (1) external domains (detected via non-null `uri.getHost()`), (2) scheme-relative URLs like `//example.com`, (3) unsafe schemes like `javascript:` or `data:`, and (4) relative paths not starting with `/`.
- **Error handling:** In each invalid case, an explanatory message is written to the response and the method returns early. The original code would have performed the redirect unconditionally.
- **Safe redirect constraint:** Only relative paths starting with `/` are allowed through to `sendRedirect()`, ensuring navigation remains within the application's own domain.

These changes eliminate the open redirect vulnerability while preserving the intended redirect functionality for safe, application-internal destinations.
