## Verdict

**CONFIRMED.** The use of `Math.random()` at line 90 to generate a "remember me" cookie token is a real CWE-330 vulnerability. `Math.random()` is a non-cryptographic PRNG unsuitable for security-relevant values. An attacker with access to a seed value or sequence of outputs can predict future token values, leading to session hijacking.

## Source

File: `BenchmarkTest00067.java`, lines 90-91 (original)

```java
double value = java.lang.Math.random();
String rememberMeKey = Double.toString(value).substring(2); // Trim off the 0. at the front.
```

The vulnerable pattern derives a session token from a weak random source. `Math.random()` is backed by a 48-bit LCG (Linear Congruential Generator) whose state is easily recoverable from observed output. Truncating or encoding it does not add entropy.

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
    private static final java.security.SecureRandom secureRandom = new java.security.SecureRandom();

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

        // SAST FINDING: CWE-330 (Use of Insufficiently Random Values) - a security-relevant value is drawn from a non-cryptographic PRNG. Sink is the next statement.
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
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

The fix replaces the non-cryptographic `Math.random()` source with `java.security.SecureRandom`, which is Java's platform CSPRNG backed by the operating system's entropy source.

**Key changes:**

1. **Add a static `SecureRandom` field** (line 34): `private static final java.security.SecureRandom secureRandom = new java.security.SecureRandom();`
   - Avoids per-request construction overhead and entropy depletion
   - `new SecureRandom()` is the safe default; `getInstanceStrong()` can block on Linux systems reading `/dev/random`

2. **Generate 16 cryptographically random bytes** (lines 94-95):
   - `byte[] randomBytes = new byte[16];` allocates 128 bits (16 bytes)
   - `secureRandom.nextBytes(randomBytes);` fills with cryptographic randomness
   - 128 bits meets OWASP ASVS requirements for non-guessable identifiers

3. **Encode to URL-safe Base64** (line 96):
   - `java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes)`
   - URL-safe alphabet (`-`, `_` instead of `+`, `/`) avoids escaping in cookies
   - Removes padding for shorter output
   - Preserves all 128 bits of entropy; Base64 encoding adds no additional entropy

The token is now cryptographically unpredictable and cannot be reverse-engineered from observed values, eliminating the session hijacking risk.
