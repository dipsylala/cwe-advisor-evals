## Verdict

exploitable

- cwe_id: CWE-330 (Use of Insufficiently Random Values)
- location: `BenchmarkTest00066.java`, line 74 (sink); the generated value is consumed at line 75
- confidence: high

## Source

`java.lang.Math.random()` at line 74. This is the value the finding flags: a general-purpose, non-cryptographic PRNG.

## Fix

### File: BenchmarkTest00066.java

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
import java.security.SecureRandom;
import java.util.Base64;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/weakrand-00/BenchmarkTest00066")
public class BenchmarkTest00066 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        javax.servlet.http.Cookie userCookie =
                new javax.servlet.http.Cookie("BenchmarkTest00066", "anything");
        userCookie.setMaxAge(60 * 3); // Store cookie for 3 minutes
        userCookie.setSecure(true);
        userCookie.setHttpOnly(true);
        userCookie.setPath(request.getRequestURI());
        userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
        response.addCookie(userCookie);
        javax.servlet.RequestDispatcher rd =
                request.getRequestDispatcher("/weakrand-00/BenchmarkTest00066.html");
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
                if (theCookie.getName().equals("BenchmarkTest00066")) {
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }

        String bar;

        // Simple if statement that assigns constant to bar on true condition
        int num = 86;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;

        byte[] randomBytes = new byte[16];
        SECURE_RANDOM.nextBytes(randomBytes);
        String rememberMeKey = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

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

`Math.random()` (backed by a 48-bit LCG in `java.util.Random`) fed `rememberMeKey`, a "remember me" authentication token that is stored server-side in the session and later accepted back from the client as proof of identity (`cookie.getValue().equals(request.getSession().getAttribute(cookieName))`). Because the generator is non-cryptographic and its state is small, an attacker who can observe or partially predict its output stream can forge a value that passes that equality check, bypassing the mechanism the cookie exists to enforce. The fix replaces the source with a single shared `SecureRandom` instance (a plain `new SecureRandom()`, not `getInstanceStrong()`, which resolves to a blocking entropy source on Linux and has caused documented production hangs) and fills a 16-byte (128-bit) buffer with `nextBytes`, meeting the OWASP ASVS floor for a non-guessable value. The bytes are encoded with `Base64.getUrlEncoder().withoutPadding()` rather than modulo-reduced or truncated, so the fix does not narrow the keyspace the new source supplies. `rememberMeKey` keeps its `String` type and is used identically downstream (stored in the session, set as the cookie value, compared with `.equals()`), so the sink's existing contract is preserved. Rotation is not applicable here: OWASP Benchmark is a synthetic, per-request test harness with no persisted prior tokens to invalidate.

## Behaviour changes

- `rememberMeKey`'s character set changes from decimal digits (the fractional digits of `Double.toString`) to URL-safe Base64 (`A-Za-z0-9-_`), and its length changes from a variable-length digit string to a fixed 22 characters. Nothing else in the file parses or expects a numeric format for this value - it is only ever used as an opaque token (stored in the session, echoed as a cookie value, compared with `.equals()`) - so this is safe.
- The comment that marked the SAST finding on the old line 74 was removed since it no longer describes the code; no other comments or logic changed.
- No other differences: control flow, method signatures, cookie attributes (`Secure`, `HttpOnly`, domain, path, max age), and all other sinks are unchanged.

## Verification

Ran `javac` against the fixed file (no build classpath available outside the project, per the no-touch restriction on the case directory and the surrounding `evals/` tree). All resulting diagnostics are pre-existing "package javax.servlet does not exist" / cascading "cannot find symbol" errors caused by `javax.servlet-api` not being on this ad hoc classpath - the same errors the unmodified file produces under the same conditions. No diagnostic referenced `SecureRandom`, `Base64`, `byte[]`, or any of the changed lines, confirming the new code is syntactically valid Java. `SecureRandom` (`java.security`) and `Base64.getUrlEncoder()` (`java.util`, added in Java 8) are both JDK standard-library APIs, matching the pattern the language guidance names.

## Assumptions

None of Step 1-3's ambiguities applied (CWE number given and matched the sink comment; language is unambiguously Java from file extension and servlet imports). The only judgment call: rotation of previously-issued values (Remediation Steps) is stated as not applicable rather than performed, because this is a stateless OWASP Benchmark test servlet with no persistent store of prior tokens to revoke.
