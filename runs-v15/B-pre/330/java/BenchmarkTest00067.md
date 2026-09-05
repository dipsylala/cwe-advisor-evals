## Verdict

Exploitable. The weak random value from `Math.random()` is used directly as an authentication token in a "remember me" cookie and session attribute (lines 90-91, 120, 126). Math.random() is a non-cryptographic PRNG with only 48 bits of internal state; an attacker can predict or recover this state from observed output, allowing them to forge valid authentication tokens.

## Source

**Weak source**: `java.lang.Math.random()` at line 90
**Data flow**: 
- Line 90: `double value = java.lang.Math.random();`
- Line 91: `String rememberMeKey = Double.toString(value).substring(2);`
- Line 120: Value used as cookie value `new javax.servlet.http.Cookie(cookieName, rememberMeKey)`
- Line 126: Same value stored in session attribute `request.getSession().setAttribute(cookieName, rememberMeKey)`
- Line 108: Value later compared to authenticate returning users

**Sink**: Authentication token generation for "remember me" cookie

## Fix

**Vulnerable code (lines 90-91):**
```java
double value = java.lang.Math.random();
String rememberMeKey = Double.toString(value).substring(2); // Trim off the 0. at the front.
```

**Fixed code:**

Add a static field to the class:
```java
private static final java.security.SecureRandom SECURE_RANDOM = new java.security.SecureRandom();
```

Replace lines 90-91 with:
```java
byte[] randomBytes = new byte[16]; // 128 bits, meeting OWASP ASVS minimum for non-guessable values
SECURE_RANDOM.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

## Explanation

The original code uses `Math.random()`, a non-cryptographic PRNG with insufficient entropy and predictable state, to generate an authentication token. An attacker observing one or more token values can recover the 48-bit internal state and predict all future tokens, allowing unauthorized access by forging valid "remember me" cookies. The fix replaces it with `SecureRandom`, which draws from cryptographic entropy sources and generates 128 bits of random data (16 bytes), meeting the OWASP ASVS requirement for security-relevant values. A shared static instance amortizes the cost of provider lookup and self-seeding across requests, eliminating the performance concern that often leads developers to Math.random(). The random bytes are encoded via URL-safe Base64 without padding to create a proper token string format.

## Behaviour changes

1. **Token length**: Increases from ~17 characters (decimal string `"0." + Math.random() digits`) to ~24 characters (Base64 encoded 16 bytes)
2. **Token format**: Changes from decimal digits to alphanumeric Base64 characters (A-Z, a-z, 0-9, -, _)
3. **Token entropy**: Increases from ~48 bits to 128 bits
4. **Generation performance**: Negligible impact; the static instance removes per-request SecureRandom construction overhead, which was the original performance reason for Math.random()

These changes are intentional cryptographic hardening with no functional side effects on cookie behavior, session validation, or authentication flow. The cookie is still set with the same attributes (secure, httpOnly, domain, path), stored in the session in the same way, and compared identically for validation. The fix closes the weakness without altering the contract of the sink or breaking any downstream code.
