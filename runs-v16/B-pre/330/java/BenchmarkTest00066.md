## Verdict

**CONFIRMED.** The vulnerability is exploitable. `java.lang.Math.random()` is a weak PRNG unsuitable for security-sensitive values. The generated `rememberMeKey` is used directly as a session cookie value (remember-me token), which an attacker can predict and forge to impersonate users.

## Source

**Sink:** Line 74, `java.lang.Math.random()` call, and the derived value at line 75.

**Data flow:**
- Line 74: `double value = java.lang.Math.random();` – weak PRNG generates predictable double
- Line 75: `String rememberMeKey = Double.toString(value).substring(2);` – truncated string representation is used as token
- Lines 103-104: Token placed into cookie: `new javax.servlet.http.Cookie(cookieName, rememberMeKey)`
- Line 110: Same token stored in session: `request.getSession().setAttribute(cookieName, rememberMeKey)`
- Line 111: Cookie sent to client: `response.addCookie(rememberMe)`

The 48-bit LCG state of `Math.random()` is recoverable from observed double output, rendering the remember-me token guessable. Encoding or truncating the output does not add entropy.

## Fix

**Replace weak PRNG with `java.security.SecureRandom`:**

```java
private static final java.security.SecureRandom secureRandom = new java.security.SecureRandom();

// In doPost(), replace lines 73-75:
// OLD:
//   double value = java.lang.Math.random();
//   String rememberMeKey = Double.toString(value).substring(2);

// NEW:
byte[] randomBytes = new byte[16];  // 128 bits
secureRandom.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

Add the static field at class level (after `serialVersionUID`, line 30):

```java
private static final java.security.SecureRandom secureRandom = new java.security.SecureRandom();
```

Update the imports to include:
```java
import java.util.Base64;
import java.security.SecureRandom;
```

## Explanation

`java.lang.Math.random()` uses a 48-bit linear congruential generator and is not suitable for any security-sensitive value, including session tokens, API keys, and remember-me cookies. Its state is recoverable from observed output, making tokens predictable.

The fix replaces it with `java.security.SecureRandom`, which uses the platform's cryptographic PRNG. A single static instance is shared across requests because `SecureRandom` is thread-safe and reusing it avoids repeated provider lookup and seeding overhead.

The fix generates 16 random bytes (128 bits), meeting OWASP ASVS's entropy floor for non-guessable values. `Base64.getUrlEncoder().withoutPadding()` encodes the bytes in URL-safe format without padding, producing a compact string suitable for cookie values.

## Behaviour changes

- **Token entropy:** Increases from ~22 bits (limited by `Math.random()` double precision) to 128 bits of cryptographic entropy.
- **Token format:** Changes from a numeric string (e.g., "123456789") to a Base64 URL-safe string (e.g., "a1b2c3d4e5f6g7h8i9j0k1l2"). Existing remember-me cookies with old format will not match the new ones; clients will be required to log in again on next visit.
- **Performance:** Negligible difference – `SecureRandom` initialization is amortized across many calls when reused.
- **Predictability:** Eliminates attacker's ability to forge tokens without guessing or observing 128 random bits.
