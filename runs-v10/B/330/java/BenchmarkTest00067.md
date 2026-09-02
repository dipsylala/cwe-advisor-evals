## Verdict

Exploitable. `java.lang.Math.random()` is a 48-bit LCG unsuitable for security-relevant tokens. The generated value becomes a session cookie used to authenticate returning users, and the entire 48-bit state is recoverable from observed tokens.

## Source

Line 90: `java.lang.Math.random()`

## Fix

**Vulnerable code:**
```java
double value = java.lang.Math.random();
String rememberMeKey = Double.toString(value).substring(2); // Trim off the 0. at the front.
```

**Fixed code:**
```java
private static final java.security.SecureRandom secureRandom = new java.security.SecureRandom();

byte[] randomBytes = new byte[16];
secureRandom.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

## Explanation

Replace `Math.random()` with `java.security.SecureRandom`, the platform's cryptographic generator. Use a shared static final instance to avoid per-request provider lookup and self-seeding overhead. Generate 16 bytes (128 bits), meeting OWASP ASVS requirements for non-guessable values. Encode via URL-safe Base64 without padding, yielding a string suitable for cookie values. The fixed code substitutes the weak source while preserving the downstream contract: a string token suitable for cookie assignment and session lookup.

## Behaviour changes

None. The fix changes only the generator and encoding mechanism. The returned value remains a string token assigned to a cookie and stored in session attributes, with the same downstream usage. The cookie attributes (secure, HttpOnly, domain, path) remain unchanged.
