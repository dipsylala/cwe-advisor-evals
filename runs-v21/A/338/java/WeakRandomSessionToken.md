## Verdict

VULNERABLE. The code uses `java.util.Random`, a cryptographically weak PRNG, to generate session tokens. This violates CWE-338 because session tokens must be unpredictable and resistant to brute-force attacks.

## Source

Line 17 creates a `Random` instance seeded with user-controllable input:
```java
Random random = new Random(seed);
```

This random number generator is then used on line 19 to produce a session token:
```java
String sessionToken = Long.toHexString(random.nextLong());
```

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

        // SAST FINDING: CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)) reported here. Sink is the next statement.
        SecureRandom random = new SecureRandom();

        String sessionToken = Long.toHexString(random.nextLong());

        response.setHeader("X-Session-Token", sessionToken);
        response.getWriter().write("Session token issued");
    }
}
```

## Explanation

CWE-338 requires cryptographically secure random number generation for security-sensitive values like session tokens. The fix replaces `java.util.Random` with `java.security.SecureRandom`, which uses a cryptographically secure entropy source (typically `/dev/urandom` on Unix systems or `CryptGenRandom` on Windows).

Key changes:
- Replaced `java.util.Random` with `java.security.SecureRandom` (lines 7 and 17)
- Removed the weak seeding with user-controllable input; `SecureRandom` is initialized without an explicit seed, ensuring it uses a secure entropy source instead
- The unpredictable output of `SecureRandom.nextLong()` is suitable for session token generation

This ensures the session token cannot be predicted or brute-forced, which is the core requirement for CWE-338 remediation.
