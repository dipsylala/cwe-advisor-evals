## Verdict

Exploitable

## Source

HTTP request parameter `seed` at line 13 (`request.getParameter("seed")`), converted to `long` at line 14.

## Fix

### File: WeakRandomSessionToken.java

```java
package evalcases;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;

public class WeakRandomSessionToken extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        SecureRandom random = new SecureRandom();

        String sessionToken = Long.toHexString(random.nextLong());

        response.setHeader("X-Session-Token", sessionToken);
        response.getWriter().write("Session token issued");
    }
}
```

## Explanation

The original code used `java.util.Random` initialized with an attacker-controlled seed from an HTTP request parameter, making session tokens completely predictable. Session tokens are security-sensitive and must use a cryptographically secure random number generator. The fix replaces `java.util.Random` with `java.security.SecureRandom`, which generates unpredictable values seeded from OS entropy. The attacker-controlled seed parameter is removed entirely, as `SecureRandom()` self-seeds securely and should never be seeded from untrusted input. This eliminates the predictability and closes the CWE-338 vulnerability.

## Behaviour changes

Removed HTTP request parameter handling (lines 13-14 in original). The fixed code no longer reads or processes the `seed` query parameter, as it is not needed for secure random generation. `SecureRandom()` initializes itself from the operating system's entropy source, providing true unpredictability. Session tokens are now cryptographically secure and non-reproducible across sessions, as intended for security-sensitive values.
