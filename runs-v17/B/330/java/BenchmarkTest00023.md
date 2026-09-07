## Verdict

exploitable

## Source

Line 48: `new java.util.Random().nextFloat()` — a security-relevant remember-me cookie token drawn from java.util.Random, a non-cryptographic PRNG.

The weak random value flows into:
- Line 49: converted to string via `Float.toString()` and trimmed
- Lines 76-84: used as a cookie value set on the response
- Line 83: stored in the session attribute

An attacker can predict this value because java.util.Random has only 48 bits of internal state and is vulnerable to seed recovery attacks.

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
import java.security.SecureRandom;
import java.util.Base64;

@WebServlet(value = "/weakrand-00/BenchmarkTest00023")
public class BenchmarkTest00023 extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final SecureRandom secureRandom = new SecureRandom();

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

        // Generate a cryptographically secure remember-me token
        byte[] randomBytes = new byte[16]; // 128 bits of entropy
        secureRandom.nextBytes(randomBytes);
        String rememberMeKey = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

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

The fix replaces the weak randomness source with Java's cryptographic PRNG. Two changes:

1. **Generator replacement**: Replaced `new java.util.Random()` with a shared `SecureRandom` instance in a `private static final` field, following CWE-330 Java guidance which states "SecureRandom objects are safe for use by multiple concurrent threads" and reusing one instance eliminates the overhead of per-request initialization.

2. **Token generation**: Replaced the derivation of a float-to-string conversion with direct byte generation. The original `float rand = new java.util.Random().nextFloat(); String rememberMeKey = Float.toString(rand).substring(2);` produced at most ~23 bits of entropy (the mantissa of a float) and was easily predictable. The fixed code generates 16 bytes (128 bits) via `secureRandom.nextBytes(randomBytes)` and encodes them as a URL-safe Base64 string via `Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes)`, meeting CWE-330's floor of 128 bits of entropy for non-guessable tokens.

This ensures the remember-me cookie token is cryptographically secure and cannot be predicted by an attacker even with knowledge of previously issued tokens.

## Behaviour changes

**Added imports**: `java.security.SecureRandom` and `java.util.Base64` are standard library, present in all supported Java versions.

**Added static field**: `private static final SecureRandom secureRandom = new SecureRandom();` — a one-time initialization cost moved out of the request path, improving throughput on token-heavy workloads.

**Token format change**: The original code produced a decimal string (e.g., "1234567") with at most 23 bits of entropy. The fixed code produces a URL-safe Base64 string (e.g., "aB_cDeFgHiJkLmNoPqRs") with 128 bits of entropy. The cookie value format differs, but its semantic role—a non-predictable session identifier—remains unchanged. Existing sessions will not carry over since the algorithm changed, forcing re-authentication on the next visit; this is correct behaviour when strengthening a token source and is expected.

**No other behaviour changes**: The cookie attributes (Secure, HttpOnly, Domain, Path), session storage, and user-facing output remain unchanged.
