## Verdict

Exploitable. Confidence: high.

- **cwe_id**: CWE-330 (Use of Insufficiently Random Values)
- **location**: `BenchmarkTest00023.java`, line 48 (source), line 49 (sink where the weak value is consumed)
- **source**: `new java.util.Random().nextFloat()` (line 48) - a non-cryptographic PRNG (48-bit LCG) seeded from system time
- **sink**: `Float.toString(rand).substring(2)` (line 49), which becomes `rememberMeKey` - stored as the session attribute `cookieName` and as the value of a persistent `rememberMe` cookie (lines 76-84), then used as the sole credential compared against on later requests (line 66) to authenticate the user without a password

## Source

`java.util.Random().nextFloat()` at line 48. The result feeds directly into `rememberMeKey`, an authentication token: it is set as a long-lived, `Secure`/`HttpOnly` cookie and as the matching session attribute, and a later request is treated as authenticated ("Welcome back") purely by comparing the presented cookie value to this stored value. There is no other check in the code path, so anything that narrows the guess space of `rememberMeKey` is a full authentication bypass, not just a quality concern. `java.util.Random` is an LCG with 48 bits of state that is fully recoverable from a handful of observed outputs, and its default seed (nano/millisecond-based) is itself guessable, so the token is far short of the 128-bit non-guessable floor this class of value needs.

## Fix

### File: BenchmarkTest00023.java

```java
/**
 * OWASP Benchmark v1.2
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project. For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Dave Wichers
 * @created 2015
 */
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/weakrand-00/BenchmarkTest00023")
public class BenchmarkTest00023 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = request.getParameter("BenchmarkTest00023");
        if (param == null) param = "";

        byte[] rememberMeKeyBytes = new byte[16];
        RANDOM.nextBytes(rememberMeKeyBytes);
        String rememberMeKey =
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(rememberMeKeyBytes);

        String user = "Floyd";
        String fullClassName = this.getClass().getName();
        String testCaseNumber =
                fullClassName.substring(
                        fullClassName.lastIndexOf('.') + 1 + "BenchmarkTest".length());
        user += testCaseNumber;

        String cookieName = "rememberMe" + testCaseNumber;

        boolean foundUser = false;
        javax.servlet.http.Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (int i = 0; !foundUser && i < cookies.length; i++) {
                javax.servlet.http.Cookie cookie = cookies[i];
                if (cookieName.equals(cookie.getName())) {
                    if (cookie.getValue().equals(request.getSession().getAttribute(cookieName))) {
                        foundUser = true;
                    }
                }
            }
        }

        if (foundUser) {
            response.getWriter().println("Welcome back: " + user + "<br/>");
        } else {
            javax.servlet.http.Cookie rememberMe =
                    new javax.servlet.http.Cookie(cookieName, rememberMeKey);
            rememberMe.setSecure(true);
            rememberMe.setHttpOnly(true);
            rememberMe.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
            rememberMe.setPath(request.getRequestURI()); // i.e., set path to JUST this servlet
            // e.g., /benchmark/sql-01/BenchmarkTest01001
            request.getSession().setAttribute(cookieName, rememberMeKey);
            response.addCookie(rememberMe);
            response.getWriter()
                    .println(
                            user
                                    + " has been remembered with cookie: "
                                    + rememberMe.getName()
                                    + " whose value is: "
                                    + rememberMe.getValue()
                                    + "<br/>");
        }

        response.getWriter().println("Weak Randomness Test java.util.Random.nextFloat() executed");
    }
}
```

## Explanation

The fix replaces the `java.util.Random`-derived token with 16 bytes (128 bits) drawn from a shared `private static final java.security.SecureRandom` instance, encoded with `Base64.getUrlEncoder().withoutPadding()` into the `rememberMeKey` string that flows into the cookie and session attribute unchanged. `SecureRandom` is a CSPRNG rather than a 48-bit LCG, so the token can no longer be recovered from observed outputs or a guessed seed, and 128 bits meets the OWASP ASVS non-guessable floor for a bearer credential. A single static `SecureRandom` field is used (per the loaded Java guidance) instead of `new SecureRandom()` per request or `getInstanceStrong()`, since the latter can resolve to a blocking entropy source on Linux and stall the request path; `SecureRandom` is documented as safe for concurrent use by multiple threads, so sharing it introduces no synchronization concern. Base64 URL-safe encoding without padding produces only `[A-Za-z0-9\-_]`, which is within the RFC 6265 `cookie-octet` character set, so no downstream cookie-parsing behavior changes. No library addition is needed - `java.security.SecureRandom` and `java.util.Base64` are JDK standard library classes, referenced fully-qualified to match this file's existing style for `javax.servlet.http.Cookie` and `java.net.URL` rather than adding new imports.

## Behaviour changes

- **Token format**: the token changes from a variable-length, purely numeric string (digits from a float's decimal representation, typically 6-9 characters) to a fixed 22-character URL-safe Base64 string (`[A-Za-z0-9\-_]`). Reason: the numeric format carried at most a few million distinct values (a `float`'s mantissa precision) and no way to reach 128 bits of entropy without changing representation; the sink (cookie value / session attribute / string equality check) treats the token opaquely, so the format change does not affect the comparison logic. `library_recommendation`: none - no new dependency, only JDK standard library classes.
- **library_recommendation**: none.
- Everything else is unchanged: same cookie name, `Secure`/`HttpOnly`/domain/path settings, session-attribute key, control flow, and response output - only the token's source and encoding changed.

**verification**: Compiled and ran the changed token-generation logic standalone with `javac`/`java` (JDK 26) in isolation from the servlet API - `SecureRandom.nextBytes(byte[16])` followed by `Base64.getUrlEncoder().withoutPadding().encodeToString(...)` compiles and produces a 22-character token (e.g. `Y7jhYPUGOLmr6ogtwvXMJA`), confirming the new API calls and types are valid. The full file was not compiled against the servlet API because no `javax.servlet-api` jar was available in this environment; by hand, every other line is unchanged from the original (which already compiles in the project), the new field `RANDOM` and local variables `rememberMeKeyBytes`/`rememberMeKey` are each declared once and used consistently, and no caller signature was touched.

**assumptions**: none - the source, sink, and fix all match the loaded root and Java CWE-330 guidance directly; no ambiguity required a resolved assumption.
