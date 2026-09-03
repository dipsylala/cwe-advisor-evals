## Verdict

Exploitable

## Source

Line 90: `javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SomeCookie", str);`

Data flows from user-controlled parameter `str` (built from request cookie value and encoded/decoded, lines 60, 68-72) into the cookie value. The vulnerability is not in the data flow but in the cookie's security configuration.

## Sink

Line 97: `response.addCookie(cookie);` — the cookie is added to the HTTP response without the Secure flag enabled.

Root cause: Line 92 explicitly sets `cookie.setSecure(false);`, marking the cookie transmissible over insecure HTTP connections.

## Fix

**Vulnerable code (line 92):**
```java
cookie.setSecure(false);
```

**Fixed code:**
```java
cookie.setSecure(true);
```

## Explanation

The Secure flag prevents the cookie from being transmitted over unencrypted HTTP connections. When `setSecure(false)` is explicitly set, the cookie will be sent in plaintext over HTTP, making it vulnerable to interception by man-in-the-middle attackers. Changing the flag to `true` ensures the browser only transmits this cookie over HTTPS connections. The cookie already has the `HttpOnly` flag set (line 93), which provides additional defence against client-side script access; setting `Secure` completes the protection by enforcing transport-layer confidentiality.

## Behaviour changes

None. The change enforces HTTPS-only transmission, which is mandatory for any cookie carrying user data. The functional contract of `response.addCookie()` remains unchanged; only the security posture of the transmitted cookie is improved.
