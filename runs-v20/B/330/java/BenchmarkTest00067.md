## Verdict

- **cwe_id**: CWE-330 (Use of Insufficiently Random Values)
- **location**: `BenchmarkTest00067.java`, line 90 (source), value consumed at lines 91, 120 and 126 (sink)
- **verdict**: exploitable
- **confidence**: high
- **library_recommendation**: none - `java.security.SecureRandom` is a JDK-standard class, no third-party dependency is introduced

## Source

`java.lang.Math.random()` at line 90 is the weak generator. Its output flows unchanged into a security-relevant value:

- Line 91: `Double.toString(value).substring(2)` strips the leading `"0."`, turning the double into a decimal-digit string (`rememberMeKey`). This is re-encoding, not new entropy - the value stays fully determined by `Math.random()`'s output.
- Line 120: `rememberMeKey` becomes the value of a `rememberMe<N>` cookie sent to the client (`Secure`, `HttpOnly`, scoped to the servlet path).
- Line 126: the same value is stored server-side via `request.getSession().setAttribute(cookieName, rememberMeKey)`.
- Lines 103-113 (a later request): the cookie value presented by the client is compared with `.equals()` against the session-stored value to decide `foundUser` - i.e. this token is used as a bearer credential that re-authenticates the user without a password.

`Math.random()` is backed by a 48-bit linear congruential generator; observing a handful of outputs lets an attacker reconstruct the internal state and predict future (or, given the digit-truncation, sometimes recover the exact) tokens. Because the token grants "remembered" login, guessing or predicting it is a full authentication bypass. This is a genuine sink for CWE-330, not a simulation/jitter use case.

## Fix

### File: BenchmarkTest00067.java

```java
/**
 * OWASP Benchmark Project v1.2
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
 * @author Nick Sanidas
 * @created 2015
 */
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/weakrand-00/BenchmarkTest00067")
public class BenchmarkTest00067 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final java.security.SecureRandom SECURE_RANDOM =
            new java.security.SecureRandom();

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        javax.servlet.http.Cookie userCookie =
                new javax.servlet.http.Cookie("BenchmarkTest00067", "anything");
        userCookie.setMaxAge(60 * 3); // Store cookie for 3 minutes
        userCookie.setSecure(true);
        userCookie.setHttpOnly(true);
        userCookie.setPath(request.getRequestURI());
        userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
        response.addCookie(userCookie);
        javax.servlet.RequestDispatcher rd =
                request.getRequestDispatcher("/weakrand-00/BenchmarkTest00067.html");
        rd.include(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

        javax.servlet.http.Cookie[] theCookies = request.getCookies();

        String param = "noCookieValueSupplied";
        if (theCookies != null) {
            for (javax.servlet.http.Cookie theCookie : theCookies) {
                if (theCookie.getName().equals("BenchmarkTest00067")) {
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }

        // Chain a bunch of propagators in sequence
        String a71153 = param; // assign
        StringBuilder b71153 = new StringBuilder(a71153); // stick in stringbuilder
        b71153.append(" SafeStuff"); // append some safe content
        b71153.replace(
                b71153.length() - "Chars".length(),
                b71153.length(),
                "Chars"); // replace some of the end content
        java.util.HashMap<String, Object> map71153 = new java.util.HashMap<String, Object>();
        map71153.put("key71153", b71153.toString()); // put in a collection
        String c71153 = (String) map71153.get("key71153"); // get it back out
        String d71153 = c71153.substring(0, c71153.length() - 1); // extract most of it
        String e71153 =
                new String(
                        org.apache.commons.codec.binary.Base64.decodeBase64(
                                org.apache.commons.codec.binary.Base64.encodeBase64(
                                        d71153.getBytes()))); // B64 encode and decode it
        String f71153 = e71153.split(" ")[0]; // split it on a space
        org.owasp.benchmark.helpers.ThingInterface thing =
                org.owasp.benchmark.helpers.ThingFactory.createThing();
        String g71153 = "barbarians_at_the_gate"; // This is static so this whole flow is 'safe'
        String bar = thing.doSomething(g71153); // reflection

        // Generate the remember-me token from a cryptographically secure source instead of
        // Math.random(), which is not suitable for a security-relevant value.
        byte[] rememberMeBytes = new byte[16]; // 128 bits, per OWASP ASVS non-guessable-value floor
        SECURE_RANDOM.nextBytes(rememberMeBytes);
        String rememberMeKey =
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(rememberMeBytes);

        String user = "Doug";
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
        response.getWriter().println("Weak Randomness Test java.lang.Math.random() executed");
    }
}
```

## Explanation

The weak generator, not just its output, is the problem: `Math.random()` was replaced with a shared `private static final java.security.SecureRandom` instance (one instance is safe for concurrent use per its Javadoc, and reusing it avoids paying provider lookup and self-seeding on every request). `nextBytes(byte[])` fills a 16-byte (128-bit) buffer, meeting the OWASP ASVS floor for a non-guessable token, and the buffer is encoded with `Base64.getUrlEncoder().withoutPadding().encodeToString(...)` rather than any modulo or digit-based reduction, so none of the newly-drawn entropy is discarded. `rememberMeKey` is otherwise used exactly as before - same cookie construction, same session-attribute storage, same equality check - so the fix only changes where the bits come from and how they are encoded, not the surrounding control flow. `getInstanceStrong()` was deliberately not used here: this code runs on a request path (`doPost`), and `getInstanceStrong()` can resolve to a blocking entropy source, which is a known cause of request-thread hangs.

## Behaviour changes

- `rememberMeKey`'s format changes from an all-decimal-digit string (the truncated `Double.toString` output) to a URL-safe Base64 string (`A-Z a-z 0-9 - _`). Nothing downstream parses or validates this value as numeric - it is only ever placed into a cookie, stored as a session attribute, and compared with `.equals()` - so the format change does not affect application behaviour.
- `rememberMeKey`'s entropy increases from whatever `Math.random()`'s ~52-bit double representation supplies (and less once truncated to a fixed-length digit string) to a full 128 bits from `SecureRandom`. This is the intended effect of the fix, not a side effect.
- A new `private static final SecureRandom SECURE_RANDOM` field was added to the class. It has no observable effect beyond supplying the random bytes above.
- No change to cookie attributes (`Secure`, `HttpOnly`, path, domain), session-attribute key, control flow, or any other statement in the file.

**Verification**: The fixed file was copied to a scratch location (not the shared case directory) alongside minimal stub versions of its non-JDK dependencies (`javax.servlet.*`, `org.apache.commons.codec.binary.Base64`, `org.owasp.benchmark.helpers.*`) and compiled with `javac` (JDK 26). It compiled with no errors - only a pre-existing deprecation note for `URLDecoder.decode(String, String)`, unrelated to this change. `java.security.SecureRandom.nextBytes(byte[])` and `java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(byte[])` are both standard `java.security`/`java.util` JDK APIs, matching the language guidance's named replacement pattern.

**Assumptions**: none - `rememberMeKey`'s consumers (cookie value, session attribute, equality check) impose no format requirement, so the Base64 encoding recommended by the language guidance was used directly without adaptation.
