## Verdict

exploitable

- **cwe_id**: CWE-614 (Sensitive Cookie Without Secure Flag)
- **location**: `BenchmarkTest00169.java`, line 85 (`response.addCookie(cookie)`)
- **confidence**: high

## Source

`doPost(HttpServletRequest request, ...)` reads the attacker-controlled HTTP header `BenchmarkTest00169` (line 44-46), URL-decodes it (line 49), and threads it through a list-manipulation and `instanceof` sequence that always resolves back to the same string (`str`, line 63-77). This value becomes the cookie's payload at `new Cookie("SomeCookie", str)` (line 78). The value's attacker-controlled origin is not itself the CWE-614 defect; the defect is the explicit `cookie.setSecure(false)` on line 80, which strips transport protection from whatever cookie is built, sensitive or not.

## Fix

Vulnerable code (lines 78-91):

```java
javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SomeCookie", str);

cookie.setSecure(false);
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
```

Fixed code:

```java
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
```

## Explanation

The cookie was built with `setSecure(false)` immediately before `response.addCookie(cookie)`, forcing the browser to send it over plain HTTP as well as HTTPS and exposing it to interception on an unencrypted or downgraded connection. Changing the argument to `setSecure(true)` (per `cwe/614/java/INDEX.md`'s core remediation: `cookie.setSecure(true)` on every sensitive cookie instantiation) makes the browser withhold the cookie from any non-HTTPS request, closing the finding at its actual sink - the attribute set on the `Cookie` object before it is added to the response. `HttpOnly` was already set and is left unchanged. No library change is applicable; this is a same-object attribute fix, not a dependency issue.

## Behaviour changes

- `cookie.setSecure(false)` -> `cookie.setSecure(true)` on line 80: this is the fix itself. The cookie will no longer be sent by the browser over a plain-HTTP connection. If any part of the deployment still serves this endpoint over HTTP (rather than HTTPS-only, per the Remediation Steps' "verify HTTPS is enforced site-wide"), the client will stop receiving/returning this cookie on that path; the app must be served over HTTPS for the cookie to reach the client at all post-fix.
- Response body text `"... secure flag set to: false"` -> `"... secure flag set to: true"`: updated only to keep the diagnostic message the servlet prints back to the caller consistent with the actual attribute now being set; it is not a security control itself and carries no independent risk, but leaving it unchanged would have made the response body assert the opposite of what the code does.
- No other arguments, return values, or control flow were altered; `HttpOnly`, `Path`, cookie name, and cookie value are unchanged from the original.
