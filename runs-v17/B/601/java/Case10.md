## Verdict
EXPLOITABLE - The vulnerability is confirmed. Untrusted data from an external URL is passed through Case10A to Case10B, where it is used directly in `response.sendRedirect()` without validating that the destination is safe. While URI syntax is validated, the code does not check whether the URL is an external domain or dangerous scheme, enabling open redirect attacks.

## Source
**Case10A.java (line 38):**
```
data = readerBuffered.readLine();
```
Reads a line from http://www.example.org/ (untrusted external source).

**Case10A.java (line 73):**
```
(new Case10B()).handleSink(data , request, response );
```
Passes untrusted data to Case10B's handleSink method.

**Case10B.java (line 32):**
```
response.sendRedirect(data);
```
Taint sink: untrusted URL sent directly as redirect destination.

## Fix
### File: Case10B.java
```java


package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;

public class Case10B
{
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
            
            // Validate redirect destination using parsed URI components
            // Reject absolute URLs with external hosts (scheme-relative URLs like //evil.com have non-null host)
            if (uri.getHost() != null)
            {
                // External URL with a domain - reject by default
                response.getWriter().write("External redirects not allowed");
                return;
            }
            
            // Reject dangerous URI schemes (javascript:, data:, etc.)
            String scheme = uri.getScheme();
            if (scheme != null && ("javascript".equalsIgnoreCase(scheme) || "data".equalsIgnoreCase(scheme)))
            {
                response.getWriter().write("Invalid redirect scheme");
                return;
            }
            
            // Only relative paths allowed - safe to redirect
            response.sendRedirect(data);
            return;
        }

    }
}
```

## Explanation
The fixed code validates the parsed URI using `getHost()` to detect external URLs, as specified in the Java guidance. The key changes:

1. **Host check**: `uri.getHost() != null` detects absolute URLs with external domains, including scheme-relative URLs like `//evil.example` that `isAbsolute()` would miss. These are rejected with an error response.

2. **Scheme validation**: Dangerous schemes like `javascript:` and `data:` are explicitly rejected, preventing protocol-based attacks.

3. **Relative paths allowed**: Only data that passes all checks (no external host, no dangerous scheme) proceeds to `sendRedirect()`. This ensures untrusted input can only redirect to relative paths on the same server.

The fix eliminates the open redirect vulnerability by enforcing the core principle: reject external domains and dangerous schemes, allowing only server-relative paths for untrusted input.

## Behaviour changes
- **Before**: External URLs and scheme-relative URLs are accepted and sent as redirects, enabling phishing and credential theft attacks.
- **After**: External URLs (detected via `getHost() != null`), scheme-relative URLs (e.g., `//attacker.com`), and dangerous schemes (javascript:, data:) are rejected with an error message. Only relative paths (e.g., `/dashboard`) are allowed.
- **User impact**: Legitimate external redirects are no longer supported through untrusted input; all redirects must be relative paths or handled through a separate, controlled allowlist mechanism.
- **Compiler verification**: Code compiles without errors. All new APIs (`getHost()`, `getScheme()`, `equalsIgnoreCase()`) are standard Java URI and String methods.
