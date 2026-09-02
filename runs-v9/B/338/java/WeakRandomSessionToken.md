## Verdict

Exploitable. Confidence: high.

- **CWE ID**: CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator)
- **Location**: `WeakRandomSessionToken.java`, line 17 (`new Random(seed)`), token produced on line 19
- **Assumptions**: None needed - the request parameter feeding the seed and the security-sensitive use (a session token issued in a response header) are both explicit in the single file provided.

## Source

`request.getParameter("seed")` (line 13) - an HTTP query/form parameter fully controlled by the caller, parsed into a `long` on line 14 with no validation or transformation.

## Fix

Library recommendation: none needed. `java.security.SecureRandom` is part of the JDK standard library; no third-party dependency or version bump applies.

Vulnerable code:

```java
package evalcases;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Random;

public class WeakRandomSessionToken extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String seedParam = request.getParameter("seed");
        long seed = Long.parseLong(seedParam);

        // SAST FINDING: CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)) reported here. Sink is the next statement.
        Random random = new Random(seed);

        String sessionToken = Long.toHexString(random.nextLong());

        response.setHeader("X-Session-Token", sessionToken);
        response.getWriter().write("Session token issued");
    }
}
```

Fixed code:

```java
package evalcases;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;

public class WeakRandomSessionToken extends HttpServlet {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String sessionToken = Long.toHexString(SECURE_RANDOM.nextLong());

        response.setHeader("X-Session-Token", sessionToken);
        response.getWriter().write("Session token issued");
    }
}
```

## Explanation

The original code seeds `java.util.Random` with a value taken directly from the `seed` request parameter, so anyone who calls the endpoint chooses the exact internal state of the generator and can compute `random.nextLong()` offline, making every issued session token fully predictable and reproducible on demand - a direct break of session-token unguessability. The fix replaces `Random` with `SecureRandom`, a CSPRNG that seeds itself from OS entropy and is never seeded from caller input, and holds one instance in a `static final` field so it is initialized once and reused across requests per the Java guidance rather than constructed per call. Because the token no longer derives from anything the caller supplies, it can no longer be predicted or reproduced.

## Behaviour changes

- The `seed` request parameter is no longer read or parsed. Honoring caller-supplied seed input for a security token's randomness is exactly the defect being fixed, so no substitute use of that parameter is appropriate; the endpoint now ignores it entirely instead of accepting and discarding it silently.
- The endpoint no longer throws `NumberFormatException` (via unhandled `Long.parseLong`) when `seed` is missing or non-numeric, since that parameter and its parsing are removed. This is a strictly safer failure mode (the endpoint now always succeeds rather than sometimes erroring on malformed input) and is a direct consequence of removing the tainted input, not an independent behavior change.
- Response contract is otherwise unchanged: same `X-Session-Token` header, same hex-encoded `long` format, same "Session token issued" body.
