## Verdict

exploitable

## Source

`new java.util.Random().nextFloat()` at line 48 generates a weak pseudorandom value using a non-cryptographic PRNG (Mersenne Twister), which has a 48-bit internal state recoverable from observed output.

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
    private static final java.security.SecureRandom secureRandom = new java.security.SecureRandom();

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

        // CWE-330 remediated: use SecureRandom with cryptographic bytes, encoded as Base64
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
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

The vulnerability was caused by using `java.util.Random().nextFloat()` to generate a remember-me token, a security-critical value that must be unpredictable. `java.util.Random` implements a Mersenne Twister PRNG with only 48 bits of internal state, making its output recoverable from observation. The fix replaces it with `java.security.SecureRandom`, a cryptographically secure pseudorandom number generator that uses the platform's entropy source (`/dev/urandom` on Unix, `CryptGenRandom` on Windows). The random bytes are generated once (16 bytes = 128 bits, meeting OWASP ASVS requirements for non-guessable tokens) and reused across requests using a static final field for efficiency. The bytes are then encoded to Base64 (URL-safe without padding) to produce a string suitable for cookie values. This ensures the remember-me token cannot be predicted by an attacker, closing the authentication bypass risk.

## Behaviour changes

1. **RandomBytes generation**: Changed from float-to-string truncation (`Float.toString(rand).substring(2)`) to byte array generation with Base64 encoding. The string length differs (variable-length float string vs. fixed 22-character Base64), but maintains suitability for cookie values.

2. **SecureRandom instance**: Introduced a shared `private static final` field to avoid repeatedly constructing and seeding `SecureRandom` instances per request, which carries significant performance cost and is recommended by the CWE-330 Java guidance.

3. **Token format and entropy**: The original approach via float truncation yields tokens with ~24 bits of entropy (2^24 possible float values from nextFloat's 24-bit mantissa). The fixed version yields 128 bits, substantially increasing the search space for token guessing from ~16 million to ~340 undecillion.

4. **Dependencies**: No new external dependencies required; uses standard Java libraries (`java.security.SecureRandom` and `java.util.Base64`, both in JDK core).

5. **API contract preserved**: The rememberMeKey remains a string used identically in cookie creation, session storage, and response output. No changes to return values, argument counts, or failure behavior of the surrounding code.
