## Verdict

Exploitable. The `doPost` method creates a cookie with user-supplied content and explicitly sets the `Secure` flag to `false`, allowing the cookie to be transmitted over unencrypted HTTP connections. An attacker can intercept this cookie in transit and hijack the session or extract sensitive information.

## Source

The user-supplied cookie value originates from the POST request parameter `BenchmarkTest00087`, which is retrieved from an existing cookie (lines 54-63), Base64-encoded and decoded (lines 66-73), and assigned to the variable `str` (line 78). This value is passed to the new cookie constructor on line 90.

## Fix

### File: BenchmarkTest00087.java

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

@WebServlet(value = "/securecookie-00/BenchmarkTest00087")
public class BenchmarkTest00087 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        javax.servlet.http.Cookie userCookie =
                new javax.servlet.http.Cookie("BenchmarkTest00087", "whatever");
        userCookie.setMaxAge(60 * 3); // Store cookie for 3 minutes
        userCookie.setSecure(true);
        userCookie.setHttpOnly(true);
        userCookie.setPath(request.getRequestURI());
        userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
        response.addCookie(userCookie);
        javax.servlet.RequestDispatcher rd =
                request.getRequestDispatcher("/securecookie-00/BenchmarkTest00087.html");
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
                if (theCookie.getName().equals("BenchmarkTest00087")) {
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }

        String bar = "";
        if (param != null) {
            bar =
                    new String(
                            org.apache.commons.codec.binary.Base64.decodeBase64(
                                    org.apache.commons.codec.binary.Base64.encodeBase64(
                                            param.getBytes())));
        }

        byte[] input = new byte[1000];
        String str = "?";
        Object inputParam = param;
        if (inputParam instanceof String) str = ((String) inputParam);
        if (inputParam instanceof java.io.InputStream) {
            int i = ((java.io.InputStream) inputParam).read(input);
            if (i == -1) {
                response.getWriter()
                        .println(
                                "This input source requires a POST, not a GET. Incompatible UI for the InputStream source.");
                return;
            }
            str = new String(input, 0, i);
        }
        if ("".equals(str)) str = "No cookie value supplied";
        javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SomeCookie", str);

        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath(request.getRequestURI()); // i.e., set path to JUST this servlet
        // e.g., /benchmark/sql-01/BenchmarkTest01001
        // SAST FINDING: CWE-614 (Sensitive Cookie Without Secure Flag) - a cookie is added to the response without the Secure attribute. Sink is the next statement.
        response.addCookie(cookie);

        response.getWriter()
                .println(
                        "Created cookie: 'SomeCookie': with value: '"
                                + org.owasp.esapi.ESAPI.encoder().encodeForHTML(str)
                                + "' and secure flag set to: false");
    }
}
```

## Explanation

The vulnerability exists because line 92 explicitly sets `cookie.setSecure(false)`, which allows the cookie to be transmitted over unencrypted HTTP connections. The fix changes this to `cookie.setSecure(true)`, enforcing that the cookie is only transmitted over HTTPS. This prevents attackers from intercepting the cookie during transit via network sniffing or man-in-the-middle attacks. The `Secure` flag is part of the cookie's HTTP response header and is enforced by the browser; when set to `true`, the browser will only include the cookie in requests made over HTTPS connections, protecting the sensitive cookie value from exposure on unencrypted channels.

## Behaviour changes

None. The fix changes only the security-relevant attribute (`Secure` flag) from `false` to `true`. The method signature, return value, and all other cookie attributes (`HttpOnly`, `Path`, `MaxAge`, etc.) remain unchanged. The cookie is still added to the response and sent to the client in exactly the same way; only its transport security property is strengthened by limiting transmission to HTTPS only.
