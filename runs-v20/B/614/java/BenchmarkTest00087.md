## Verdict

exploitable

- cwe_id: CWE-614
- location: `BenchmarkTest00087.java`, line 97 (`response.addCookie(cookie)`)
- confidence: high

## Source

`doPost` builds `str` from the incoming `BenchmarkTest00087` request cookie (URL-decoded at line 60, round-tripped through Base64 at lines 68-73, then re-derived through the `inputParam` string/InputStream branch at lines 76-88). This value is used verbatim as the value of a newly created cookie, `SomeCookie`, at line 90.

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
        response.addCookie(cookie);

        response.getWriter()
                .println(
                        "Created cookie: 'SomeCookie': with value: '"
                                + org.owasp.esapi.ESAPI.encoder().encodeForHTML(str)
                                + "' and secure flag set to: true");
    }
}
```

## Explanation

`cookie.setSecure(false)` at line 92 explicitly marked `SomeCookie` as transmittable over plain HTTP, so the browser would send it (and the attacker-influenced value it carries) in cleartext, exposing it to interception on an unencrypted connection. Changing the call to `cookie.setSecure(true)` sets the `Secure` attribute so the browser only ever sends this cookie back over HTTPS, closing the CWE-614 finding at the `response.addCookie(cookie)` sink on line 97. `HttpOnly` was already set and is left untouched. The trailing status message, which literally reports the flag's value back to the caller ("...and secure flag set to: false"), was updated to "true" so the printed message continues to describe the code's actual behavior rather than becoming stale/incorrect after the fix; this is not itself a security control, just keeping the diagnostic output truthful.

## Behaviour changes

- `cookie.setSecure(true)` (was `false`): the `SomeCookie` cookie the browser stores will now only be sent back over HTTPS connections, never over plain HTTP. This is the intended effect of the fix, not a side effect.
- Response body text changed from `"...secure flag set to: false"` to `"...secure flag set to: true"`: required so the diagnostic message stays consistent with the corrected flag value; no other output or return value was altered.
- No other arguments, return values, control flow, or discarded output were changed.
- verification: copied the file to a scratch directory and compiled with `javac` (JDK 26). The servlet/commons-codec/ESAPI dependencies are not on the ad hoc classpath, so both the original and fixed copies produce the same "package does not exist" / "cannot find symbol" errors for those imports and the resulting "does not override a method from a supertype" cascade; a line-by-line diff of the two compiler outputs showed no new or different errors introduced by the fix, confirming the change is syntactically sound. All new/changed tokens (`setSecure`, `true`) are pre-existing symbols already used elsewhere in the same file (e.g. `userCookie.setSecure(true)` in `doGet`), so no unverified names were introduced.
