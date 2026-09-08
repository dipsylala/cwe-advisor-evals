## Verdict

exploitable

- **cwe_id**: CWE-338
- **location**: `WeakRandomSessionToken.java`, line 17 (sink), fed by line 13-14 (source)
- **confidence**: high

## Source

- **Source**: `request.getParameter("seed")` (line 13), an attacker-controlled HTTP request parameter, parsed to a `long` via `Long.parseLong(seedParam)` (line 14).
- **Sink**: `new Random(seed)` (line 17), a `java.util.Random` instance explicitly seeded with that attacker-controlled value.
- **Data flow**: the request parameter flows unmodified and unvalidated into the `Random` constructor's seed, and the resulting generator immediately produces the value returned as the session token (`random.nextLong()`, line 19), which is placed directly on the HTTP response as `X-Session-Token` (line 21). There is no sanitization, bounding, or intervening use between source and sink - this is a direct, single-hop taint path, and it is worse than a merely-weak PRNG: `java.util.Random`'s generator is a public, reversible linear congruential algorithm, and here the attacker supplies the seed itself, so anyone who sends a request can compute the exact resulting `sessionToken` for that request without needing to break the algorithm at all.
- **Sink contract**: `new Random(seed)` returns a `java.util.Random` instance seeded deterministically; `nextLong()` returns the next pseudorandom value in that fully-determined sequence. Nothing is discarded. The only implicit/omitted piece is that the constructor's seed argument is taken from untrusted input rather than from a secure entropy source - that is the defect itself, not a side default. Failure behaviour: `Long.parseLong(seedParam)` throws `NumberFormatException` (uncaught, propagates as a container error response) if `seed` is missing or non-numeric; this failure path is unrelated to CWE-338 and is removed as a consequence of no longer needing the parameter (see Behaviour changes).

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

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String sessionToken = Long.toHexString(SECURE_RANDOM.nextLong());

        response.setHeader("X-Session-Token", sessionToken);
        response.getWriter().write("Session token issued");
    }
}
```

**library_recommendation**: none - the fix uses `java.security.SecureRandom`, part of the Java standard library, not a third-party dependency.

## Explanation

The vulnerable code seeded a `java.util.Random` - a predictable, publicly-specified PRNG - with a value taken directly from an HTTP request parameter, then used its next output as a session token; this let any caller compute their own (or, by resending the same `seed`, any other) session token deterministically. The fix replaces `java.util.Random` with a single shared `java.security.SecureRandom` instance (per the language guidance's recommendation to initialize once and reuse rather than construct per call), created with the no-argument constructor so it self-seeds from the JVM's secure entropy source. The request's `seed` parameter is no longer read or used to influence the generator at all: per the loaded guidance, a `SecureRandom` explicitly constructed or seeded from a caller-supplied value is exactly as predictable as the value supplied, so removing attacker control of the seed - not merely swapping the generator class - is what closes this specific finding. `nextLong()` is called the same way as before, so the token's format (a hex string) and how it is delivered (the `X-Session-Token` response header) are unchanged.

## Behaviour changes

- **Removed the `seed` request parameter and its parsing (`request.getParameter("seed")`, `Long.parseLong(seedParam)`).** Reason: this was the sole vector by which the token became attacker-predictable; retaining it as dead input (read but unused) would leave a landmine for a future edit to wire back into the generator, and per the surgical-changes rule, code that a fix's own change makes unused should be removed rather than left in place. This also removes the `NumberFormatException` failure path that occurred when `seed` was missing or non-numeric (the endpoint no longer requires or reads that parameter). Any caller of this endpoint that supplied `seed` expecting to reproduce a specific token was relying on the vulnerable behaviour itself and cannot be preserved without reintroducing the weakness.
- **`Random` instance is now a shared `static final SecureRandom` instead of one `new Random(seed)` per request.** Reason: matches the loaded guidance ("Initialize `SecureRandom` once and reuse the instance to avoid performance overhead"); `SecureRandom` is thread-safe for concurrent `nextLong()` calls, so sharing it across requests is safe.
- All other behaviour is unchanged: `nextLong()` is still hex-encoded via `Long.toHexString`, still set on the `X-Session-Token` response header, and the same `"Session token issued"` body is written.

**verification**: `javac` (JDK 26) run against the fixed file in a scratch directory outside the codebase. It reported only "package javax.servlet.http does not exist" and the resulting cascade errors - expected, since the servlet-api dependency is not on this environment's classpath (the original file fails identically for the same reason). No errors were reported against any of the fix's own additions (`java.security.SecureRandom`, the `SECURE_RANDOM` field, or the rewritten `doGet` body), confirming the change introduces no new symbol or syntax errors.

**assumptions**: none - the CWE ID matched the description, the language (Java) was unambiguous from file extension and imports, and the loaded root/language guidance directly covers this sink (`new Random(seed)`) with no ambiguity requiring a resolved assumption.
