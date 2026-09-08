## Verdict

Confirmed. `java.util.Random` is a non-cryptographic PRNG whose output is predictable given the seed (derived from system time by default) and, once even a few outputs are observed, its internal state can be recovered and future/past outputs predicted. Here its output becomes the value of a "remember me" authentication cookie, so an attacker who can predict or brute-force `rememberMeKey` can forge a valid persistent-login cookie for another user without knowing their credentials.

## Source

`E:/Github/cwe-advisor/evals/cases/330/java/BenchmarkTest00023/BenchmarkTest00023.java`, line 48:

```java
float rand = new java.util.Random().nextFloat();
String rememberMeKey = Float.toString(rand).substring(2); // Trim off the 0. at the front.
```

The result flows unmodified into `rememberMeKey`, which is stored as the session attribute and used as the value of the `rememberMe<N>` cookie set on the response (lines 76-87) and later trusted for re-authenticating the user (lines 65-71).

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
import java.security.SecureRandom;
import java.util.Base64;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

        byte[] randomBytes = new byte[20];
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

`java.util.Random` uses a 48-bit linear congruential generator that is not designed to resist prediction; it is unsuitable for anything that gates access or identity, such as a remember-me token. The fix replaces it with `java.security.SecureRandom`, a cryptographically strong generator, and draws the token from a fixed-size byte buffer (20 bytes = 160 bits of entropy) rather than from the decimal digits of a `float`, which have far less entropy and a non-uniform distribution than the underlying random bits. The `SecureRandom` instance is created once as a `static final` field rather than per-request, since repeated instantiation is wasteful and unnecessary (a single instance is thread-safe for concurrent `nextBytes` calls).

The raw bytes are encoded with `Base64.getUrlEncoder().withoutPadding()` rather than manual hex conversion, producing a compact, cookie-safe token (the URL-safe alphabet avoids `+`, `/`, and `=`, none of which need any additional escaping in a cookie value). This is a drop-in replacement: `rememberMeKey` keeps its type and role, so the equality check against the session-stored value and the cookie construction downstream require no changes.
