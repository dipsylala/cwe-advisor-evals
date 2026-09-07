## Verdict

Exploitable. The vulnerability allows an attacker to predict session tokens by observing or controlling the seed parameter, compromising session security.

## Source

`request.getParameter("seed")` at line 13 provides user-controlled input that is parsed to a `long` and passed to the weak PRNG at line 17.

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

        // Fixed: Use SecureRandom instead of java.util.Random for cryptographically secure token generation
        SecureRandom random = new SecureRandom();

        String sessionToken = Long.toHexString(random.nextLong());

        response.setHeader("X-Session-Token", sessionToken);
        response.getWriter().write("Session token issued");
    }
}
```

## Explanation

The vulnerability was replaced by two changes: (1) Import `java.security.SecureRandom` instead of `java.util.Random` at the top of the file, and (2) Replace `new Random(seed)` with `new SecureRandom()` at line 17. `java.util.Random` is a predictable, general-purpose PRNG unsuitable for security-sensitive operations like session token generation; it becomes particularly weak when seeded with limited entropy or user-controlled values. `SecureRandom` provides cryptographically secure randomness by using the underlying operating system's entropy source (e.g., `/dev/urandom` on Linux), automatically seeded and guaranteed to be unpredictable. This eliminates the prediction vector: session tokens are now non-reproducible even if an attacker knows the seed parameter, because the seed parameter is no longer used for token generation.

## Behaviour changes

The endpoint no longer uses the `seed` request parameter for random token generation. This is the intended fix: session tokens must not be seeded with user-controlled or predictable values. The tokens are now generated from cryptographic entropy and are unpredictable across sessions, which is the correct behaviour for security-sensitive session identification.
