## Verdict

exploitable

## Source

The request header value at lines 44-45 (`request.getHeader("BenchmarkTest00169")`), URL decoded at line 49, and assigned to the cookie at line 78. The unencrypted HTTP transmission path is confirmed by the explicit `setSecure(false)` at line 80.

## Fix

### File: BenchmarkTest00169.java

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

@WebServlet(value = "/securecookie-00/BenchmarkTest00169")
public class BenchmarkTest00169 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        if (request.getHeader("BenchmarkTest00169") != null) {
            param = request.getHeader("BenchmarkTest00169");
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String bar = "alsosafe";
        if (param != null) {
            java.util.List<String> valuesList = new java.util.ArrayList<String>();
            valuesList.add("safe");
            valuesList.add(param);
            valuesList.add("moresafe");

            valuesList.remove(0); // remove the 1st safe value

            bar = valuesList.get(1); // get the last 'safe' value
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

The vulnerability exists because line 80 explicitly sets `cookie.setSecure(false)`, which allows the cookie containing the header value to be transmitted over unencrypted HTTP connections, exposing it to interception and man-in-the-middle attacks. The fix changes this to `cookie.setSecure(true)`, which enforces transmission only over HTTPS and prevents the cookie from being sent over insecure channels. This aligns with CWE-614 remediation guidance for Java cookies and ensures that sensitive cookie data (in this case derived from the request header) is protected by the transport layer.

## Behaviour changes

None. The `setSecure(true)` method call modifies only the cookie's secure flag attribute; it does not change the cookie's value, the return type, any exception behavior, or any other contract of the `response.addCookie()` sink. The cookie still contains the same value, is still set as HttpOnly, and is still added to the response in the same way. The only change is the security attribute that controls which transport protocol (HTTPS vs. HTTP) the browser uses when transmitting the cookie.
