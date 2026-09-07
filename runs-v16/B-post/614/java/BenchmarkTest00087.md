## Verdict
exploitable

## Source
User-supplied parameter `param` read from cookie value (line 60) and decoded with `URLDecoder.decode()`. Parameter is transformed through Base64 encode/decode cycle and assigned to `str` (lines 68-72), which becomes the cookie value.

## Fix
**Vulnerable code (line 90-97):**
```java
javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SomeCookie", str);

cookie.setSecure(false);
cookie.setHttpOnly(true);
cookie.setPath(request.getRequestURI());
response.addCookie(cookie);
```

**Fixed code:**
```java
javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SomeCookie", str);

cookie.setSecure(true);
cookie.setHttpOnly(true);
cookie.setPath(request.getRequestURI());
response.addCookie(cookie);
```

## Explanation
The cookie containing the user-supplied parameter is created without HTTPS-only transmission protection. Line 92 explicitly sets `setSecure(false)`, allowing the cookie to be transmitted over unencrypted HTTP connections where it can be intercepted by attackers performing man-in-the-middle attacks. The fix changes this to `setSecure(true)`, enforcing that the cookie is only transmitted over HTTPS. This is a single-argument change to an existing method call that requires no additional imports or dependencies beyond those already in scope.

## Behaviour changes
**Output message (line 103):** The message printed to the response changes from "secure flag set to: false" to "secure flag set to: true". This is a logging/informational change that reflects the actual security posture and has no functional impact on the application's behavior beyond the intended security fix.

**Sink contract:** The `response.addCookie()` call's contract remains unchanged - it still accepts a `Cookie` object and adds it to the response headers. The only difference is that the cookie now includes the `Secure` attribute in the `Set-Cookie` header, limiting transmission to HTTPS only.
