## Verdict
exploitable

## Source
The vulnerability originates at line 13 where an HTTP request parameter `seed` is extracted via `request.getParameter("seed")`. This attacker-controlled seed is then parsed as a long and passed to the weak `java.util.Random` constructor at line 17, allowing an attacker to reproduce the random values used to generate the session token.

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
        String seedParam = request.getParameter("seed");
        long seed = Long.parseLong(seedParam);

        // Fixed: Use SecureRandom instead of weak java.util.Random
        SecureRandom random = new SecureRandom();

        String sessionToken = Long.toHexString(random.nextLong());

        response.setHeader("X-Session-Token", sessionToken);
        response.getWriter().write("Session token issued");
    }
}
```

## Explanation
The fix replaces `java.util.Random` with `java.security.SecureRandom`, which provides cryptographically secure random number generation. The original code seeded Random with an attacker-controlled parameter from the HTTP request, making session tokens reproducible by an attacker who knows the seed value. SecureRandom initializes itself from the operating system's entropy source and does not accept a seed parameter in this context, ensuring tokens are unpredictable and non-reproducible. This eliminates the ability for an attacker to forge valid session tokens.

## Behaviour changes
The seed parameter from the request is no longer used to seed the random number generator. Instead, SecureRandom initializes itself from the operating system's entropy source. As a result, session tokens will no longer be reproducible using the seed parameter from the request. This is the correct behavior for a security-sensitive token generation operation, as session tokens must be unpredictable and unique across sessions. Any code that relied on reproducing tokens from a known seed should be updated to handle the new non-deterministic token generation.
