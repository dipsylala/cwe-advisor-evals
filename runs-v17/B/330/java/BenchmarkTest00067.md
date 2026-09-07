## Verdict

exploitable

## Source

`java.lang.Math.random()` at line 90 of BenchmarkTest00067.java

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
    private static final java.security.SecureRandom SECURE_RANDOM = new java.security.SecureRandom();

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

        // Generate a cryptographically secure random token
        byte[] randomBytes = new byte[16]; // 128 bits
        SECURE_RANDOM.nextBytes(randomBytes);
        String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

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

The original code used `Math.random()` to generate a token for the "remember me" cookie. `Math.random()` is a general-purpose PRNG based on a 48-bit linear congruential generator whose output is fully predictable if the internal state is known or can be brute-forced over the narrow state space. An attacker can forge valid remember-me tokens and bypass authentication checks.

The fix replaces the weak random source with `java.security.SecureRandom`, which uses the platform's cryptographically secure PRNG. The fix generates 128 bits of random data (16 bytes), meeting OWASP ASVS requirements for security-relevant values. The bytes are encoded as base64-url format for safe use in cookies. The `SecureRandom` instance is stored in a static field to avoid per-request initialization overhead and because `SecureRandom` is thread-safe and designed for concurrent use.

## Behaviour changes

**Added static field:** Line 31 adds `private static final java.security.SecureRandom SECURE_RANDOM = new java.security.SecureRandom();` to store the cryptographic generator. The field is instantiated once at class load time and reused across all requests. No change to visible behaviour; thread safety and entropy are enhanced.

**Replaced random generation:** Lines 90-91 are replaced with lines 90-93. The output format differs: the original produced a decimal string like "0.123456789" truncated to "123456789", while the new code produces a 24-character base64-url string (128 bits encoded). The cookie value length and character set differ, but the same `rememberMeKey` variable is used downstream without changes, so authentication logic remains intact.

**Token entropy:** The original code produced at most 48 bits of entropy (the state space of the 48-bit LCG). The fix produces exactly 128 bits, meeting cryptographic standards for security-relevant values.

**No external dependencies:** The fix uses only Java standard library classes (`java.security.SecureRandom`, `java.util.Base64`). No new dependencies required.

