## Verdict

Exploitable. `java.util.Random` is a non-cryptographic, statistically-predictable PRNG, and here it is worse than the typical instance of this finding: it is explicitly seeded with a value read directly from the HTTP request (`request.getParameter("seed")`). An attacker who supplies `?seed=<any long>` fully determines the PRNG's internal state and can compute `random.nextLong()` offline before the request is even sent, giving them the exact `X-Session-Token` value the server will issue. This is not merely predictable randomness - it is attacker-chosen output. Confidence: high.

## Source

`request.getParameter("seed")` at line 13 of `WeakRandomSessionToken.java`, parsed to `long seed` at line 14. That value flows unmodified into the sink at line 17, `new Random(seed)`, whose output (`random.nextLong()`, line 19) becomes the entire `sessionToken` value written to the `X-Session-Token` response header (line 21). No validation, transformation, or additional entropy is applied anywhere along this path.

## Fix

No third-party library is needed - `java.security.SecureRandom` is part of the JDK standard library, so no dependency/manifest change applies here.

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

The fix replaces the attacker-seedable `new Random(seed)` with a single, class-level `SecureRandom` instance, initialized once and reused across requests as the language guidance directs (avoids the per-request construction overhead and matches the "initialize once, reuse the instance" principle). Because the token is a single scalar value rather than a value composed from several bounded `nextInt()` calls, `nextLong()` on the CSPRNG instance is not the biased-composition pattern the guidance warns against, so it is kept in the same `Long.toHexString(...)` form as the original for a minimal, behavior-preserving change. The critical part of the fix is not "swap Random for SecureRandom" alone - it is removing the request-controlled seed entirely. `SecureRandom` draws from OS entropy and exposes no equivalent constructor-seed pathway for its default algorithm, so there is no remaining input by which a caller can steer the output. The `seed` request parameter is consequently no longer read at all, since it served no purpose in the vulnerable code other than being fed into the PRNG.

## Behaviour changes

- The `seed` query parameter is no longer read or required. Previously a request with no `seed` parameter, or a non-numeric one, threw `NumberFormatException` from `Long.parseLong(null)`/`Long.parseLong(seedParam)`, which the servlet container would turn into a 500 response; the fixed endpoint now succeeds unconditionally and ignores that parameter if present. This is required by the fix: the seed parameter was the injection point that made the token attacker-chosen, so no replacement for it is introduced.
- Every call to the endpoint now returns a token drawn from a fresh CSPRNG output rather than a value reproducible by supplying the same `seed`. This is the intended effect of the fix, not an incidental change.
- Token format, length, header name, response body text, and all other control flow are unchanged: still a 16-hex-character `Long.toHexString` value in the `X-Session-Token` header followed by the same body write.
