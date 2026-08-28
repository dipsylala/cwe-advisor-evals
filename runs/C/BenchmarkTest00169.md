## Fix
```java
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
        response.addCookie(cookie);

        response.getWriter()
                .println(
                        "Created cookie: 'SomeCookie': with value: '"
                                + org.owasp.esapi.ESAPI.encoder().encodeForHTML(str)
                                + "' and secure flag set to: true");
    }
```

## Explanation
The cookie carrying the request-derived value was built with `setSecure(false)` and then added to the response, so a browser would send it back over plain HTTP as well as HTTPS, exposing it to interception or modification by anyone on the network path. Setting `cookie.setSecure(true)` before `response.addCookie(cookie)` marks the cookie `Secure`, restricting transmission to HTTPS connections only; `setHttpOnly(true)` is kept so client-side script still cannot read it, and the echoed status message was updated to match the flag actually set. The `Secure` attribute only helps if the deployment serves the application over HTTPS, so confirm transport security is enforced site-wide; `SameSite` cannot be expressed through the Servlet `Cookie` API and should be configured at the container level (`SessionCookieConfig`, `web.xml`, or application properties), choosing `Lax` or `Strict` according to whether inbound links or SSO callbacks need the cookie.
