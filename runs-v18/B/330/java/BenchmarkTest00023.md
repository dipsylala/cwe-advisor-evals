## Verdict
EXPLOITABLE: `java.util.Random` generates a "remember me" session token with insufficient entropy, allowing an attacker to predict or forge authentication cookies.

## Source
Line 48 in `BenchmarkTest00023.java`:
```java
float rand = new java.util.Random().nextFloat();
String rememberMeKey = Float.toString(rand).substring(2);
```

The `java.util.Random` is a non-cryptographic PRNG used to generate a security-relevant value (session token). The resulting token is stored as a cookie (line 76–84) and validated on subsequent requests (lines 61–71).

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

        // Generate a cryptographically strong random token using SecureRandom
        byte[] randomBytes = new byte[16]; // 128 bits of entropy
        new java.security.SecureRandom().nextBytes(randomBytes);
        String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

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
The fix replaces the non-cryptographic `java.util.Random` with `java.security.SecureRandom`, which uses the platform's cryptographic random source. Instead of converting a float to a string, the fixed code generates 16 bytes (128 bits) of random data and encodes it as a URL-safe Base64 string. This produces a token with sufficient entropy to resist brute-force and prediction attacks. The `SecureRandom` instance is created fresh for this request; the Javadoc confirms it is safe for concurrent use, and on-demand creation is acceptable for request-scoped token generation. The token remains stored and validated identically (in the session and cookie), so the authentication flow is unchanged.

## Behaviour changes
- **Randomness quality**: The token is now drawn from `java.security.SecureRandom` (cryptographic) instead of `java.util.Random` (statistical).
- **Entropy**: The token now carries 128 bits of entropy from 16 random bytes, encoded in Base64, versus approximately 24 bits from a float's mantissa.
- **Token format**: The token format changes from a truncated float string (e.g., "123456789") to a Base64-encoded string (e.g., "aBcD1234..."). The cookie and session comparison logic remain unchanged because both use `String.equals()`.
- **Performance**: A negligible cost is added by calling `SecureRandom.nextBytes()` once per token generation; this is unavoidable when using cryptographic randomness and is appropriate for security-relevant tokens.
