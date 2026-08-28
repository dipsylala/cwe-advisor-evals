## Fix

```java
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
```

## Explanation

The cookie was created and explicitly marked `cookie.setSecure(false)` before being handed to `response.addCookie(...)`, so the container emitted a `Set-Cookie` header with no `Secure` attribute and the browser would return that cookie over plain HTTP as well as HTTPS, exposing its value to anyone able to observe or tamper with unencrypted traffic. Setting `cookie.setSecure(true)` at the same instantiation point makes the browser withhold the cookie on any non-HTTPS request, which is the transport-layer confinement this weakness is about; the existing `setHttpOnly(true)` is retained so the value is also unreachable from client-side script, and the response text was corrected so it no longer reports a flag state that contradicts what is actually sent. Because the Servlet `Cookie` class exposes no `SameSite` setter, any cross-site restriction for this cookie belongs in the container's session-cookie configuration or a `Set-Cookie` written via `ResponseCookie`, chosen as `Lax` or `Strict` per flow; the `Secure` flag itself only takes effect where HTTPS is enforced, so the deployment must serve this servlet over TLS for the fix to hold on the wire.
