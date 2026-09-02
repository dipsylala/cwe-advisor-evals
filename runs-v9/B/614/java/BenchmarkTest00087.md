## Verdict

exploitable (confidence: high)

- CWE-614 - Sensitive Cookie Without Secure Flag
- Location: `BenchmarkTest00087.java`, `doPost`, line 97 (`response.addCookie(cookie)`); the defect is set at line 92 (`cookie.setSecure(false)`).

## Source

`javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SomeCookie", str)` at line 90. `str` is derived from the incoming POST request's `BenchmarkTest00087` cookie value (URL-decoded, then passed through a Base64 encode/decode round trip), with a hardcoded fallback string if no cookie is present. The cookie is explicitly constructed with `cookie.setSecure(false)` at line 92, then added to the response with `response.addCookie(cookie)` at line 97 - the sink. No code path between construction and the sink sets `secure` to `true`, so every response carrying this cookie instructs the browser it may be sent over plain HTTP.

## Fix

Vulnerable code (lines 90-97):

```java
javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SomeCookie", str);

cookie.setSecure(false); // CWE-614: cookie explicitly marked non-secure
cookie.setHttpOnly(true);
cookie.setPath(request.getRequestURI()); // i.e., set path to JUST this servlet
// e.g., /benchmark/sql-01/BenchmarkTest01001
// SAST FINDING: CWE-614 (Sensitive Cookie Without Secure Flag) - a cookie is added to the response without the Secure attribute. Sink is the next statement.
response.addCookie(cookie);
```

Fixed code:

```java
javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SomeCookie", str);

cookie.setSecure(true);
cookie.setHttpOnly(true);
cookie.setPath(request.getRequestURI()); // i.e., set path to JUST this servlet
// e.g., /benchmark/sql-01/BenchmarkTest01001
response.addCookie(cookie);
```

The status message that echoes the cookie's flag back to the client must be updated to match, otherwise the response text misrepresents the cookie actually sent:

```java
response.getWriter()
        .println(
                "Created cookie: 'SomeCookie': with value: '"
                        + org.owasp.esapi.ESAPI.encoder().encodeForHTML(str)
                        + "' and secure flag set to: true");
```

## Explanation

The single-line change (`setSecure(false)` -> `setSecure(true)`) closes the finding: it tells the browser to withhold `SomeCookie` on any non-HTTPS request, so it can no longer be captured by a network-position attacker on plain HTTP. `HttpOnly` was already set and is left unchanged. Per the Java-specific guidance, this per-cookie call is required regardless of any container-level `server.servlet.session.cookie.secure` setting, since this is a manually constructed `Cookie` object, not the container-managed session cookie. This code path predates Jakarta Servlet 6.0, so no `SameSite` attribute is available on this `Cookie` type; that would need to be set at the container/session-config level and is out of scope for this finding.

## Behaviour changes

- `cookie.setSecure(true)` (was `false`) - the cookie is now withheld by the browser on plain-HTTP requests. This is the intended effect of the fix; any test or client that currently reads `SomeCookie` back over an HTTP (non-TLS) connection will stop receiving it. No such dependency should exist in a production HTTPS deployment.
- The hardcoded string `"and secure flag set to: false"` was changed to `"...true"` to keep the diagnostic response text accurate against the cookie actually being sent. This has no security effect; it is a direct, necessary consequence of the flag flip, not an independent change.
- No other arguments, return values, or control flow were altered. `HttpOnly`, `Path`, `MaxAge` (unset, framework default), and the cookie's name/value are unchanged.

Assumption: the cookie value (`SomeCookie`, sourced from request-controlled input) is treated as sensitive per the finding's classification, consistent with this file's `doGet` counterpart cookie which is already built with `setSecure(true)`.
