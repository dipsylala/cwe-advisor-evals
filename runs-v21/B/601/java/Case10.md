## Verdict
Exploitable

## Source
External URL content from `http://www.example.org/` read via `BufferedReader.readLine()` in Case10A.java, line 38, passed to Case10B.handleSink() as the `data` parameter.

## Sink
`response.sendRedirect(data)` at Case10B.java, line 32.

## Fix

### File: Case10B.java

```java

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;

public class Case10B
{
    // Allowlist of safe redirect destinations
    private static final Set<String> SAFE_HOSTS = new HashSet<>();
    static {
        SAFE_HOSTS.add("www.example.org");
        SAFE_HOSTS.add("example.org");
    }

    private static boolean isValidRedirect(String redirectUrl) {
        URI uri;
        try {
            uri = new URI(redirectUrl);
        } catch (URISyntaxException e) {
            return false;
        }
        
        // If the URI has a host, it's an absolute or protocol-relative URL
        if (uri.getHost() != null) {
            // Validate against allowlist
            return SAFE_HOSTS.contains(uri.getHost());
        }
        
        // If no host and absolute (like javascript:), reject
        if (uri.isAbsolute()) {
            return false;
        }
        
        // Relative paths (no host, not absolute) are allowed
        return true;
    }

    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        if (data != null)
        {
            // Validate redirect URL against allowlist
            if (!isValidRedirect(data)) {
                response.getWriter().write("Invalid redirect URL");
                return;
            }
            
            response.sendRedirect(data);
            return;
        }

    }
}
```

## Explanation

The vulnerability allows an attacker to control the redirect destination by providing a malicious URL in the external response. The original code only validated URI syntax but not the destination domain, allowing redirects to untrusted sites like `https://evil.com`.

The fix introduces an allowlist-based validator that:
1. Parses the URL into a URI object and rejects invalid syntax
2. Checks for the presence of a host (`uri.getHost() != null`), which catches both absolute URLs (`https://evil.com`) and protocol-relative URLs (`//evil.com`)
3. Validates the host against an allowlist of trusted domains (`www.example.org`, `example.org`)
4. Rejects absolute URIs with no host (like `javascript:alert(1)`) per the guidance
5. Allows relative paths (those with no host and not absolute) like `/dashboard` or `?param=value`

This ensures that only redirects to trusted destinations proceed, while untrusted external URLs are rejected with an error message.

## Behaviour changes

- Added `SAFE_HOSTS` static allowlist containing trusted redirect destinations (`www.example.org`, `example.org`). Reason: core defence mechanism to enforce server-controlled redirect targets.
- Added `isValidRedirect()` method to encapsulate redirect validation logic. Reason: reusable validator per the guidance's recommendation for centralized enforcement.
- Inserted validation check before `response.sendRedirect()` call. Reason: gates the sink to trusted URLs only, closing the open redirect.
- Error response differs: returns early with error message instead of proceeding to untrusted redirect. Reason: explicit rejection of invalid redirects; this is a security-critical behaviour change.

## Verification

`javac` compilation: successful. Fixed code compiled without errors. All new symbols (`URI`, `URISyntaxException`, `HashSet`, `Set`) are from `java.net` and `java.util`, both part of the Java standard library and already imported via the guidance-recommended packages.
