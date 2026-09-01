## Verdict

Exploitable. The weak random value is used directly as a session authentication token (remember-me cookie and session attribute). An attacker can predict `java.util.Random` output (48-bit LCG state) and forge valid session credentials.

## Source

Line 48: `float rand = new java.util.Random().nextFloat();`

The source is a non-cryptographic pseudo-random number generator unsuitable for security-relevant values.

## Fix

**Vulnerable code (lines 47-49):**
```java
// SAST FINDING: CWE-330 (Use of Insufficiently Random Values) - a security-relevant value is drawn from a non-cryptographic PRNG. Sink is the next statement.
float rand = new java.util.Random().nextFloat();
String rememberMeKey = Float.toString(rand).substring(2); // Trim off the 0. at the front.
```

**Fixed code:**

Add a field at class level:
```java
private static final java.security.SecureRandom secureRandom = new java.security.SecureRandom();
```

Replace lines 48-49 with:
```java
byte[] randomBytes = new byte[16]; // 128 bits minimum per OWASP ASVS
secureRandom.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

## Explanation

The fix replaces `java.util.Random` (a predictable 48-bit linear congruential generator) with `java.security.SecureRandom`, which provides cryptographically strong randomness. The output is sized to 128 bits (16 bytes) per OWASP ASVS minimum for non-guessable session tokens, and encoded to a URL-safe base64 string for use as a cookie value. A shared static `SecureRandom` instance is used to avoid repeated provider lookup and self-seeding on each request, following the Java language guidance's recommendation over `getInstanceStrong()` which can block indefinitely on Linux systems. The cookie and session attribute now carry a genuinely unpredictable value, preventing token forgery attacks.

## Behaviour changes

- **Random source:** `java.util.Random` → `java.security.SecureRandom` (provides cryptographic entropy instead of predictable 48-bit LCG)
- **Entropy size:** ~32 bits (float precision) → 128 bits (16 bytes), meeting OWASP ASVS minimum for tokens
- **Encoding:** `Float.toString()` substring → `Base64.getUrlEncoder().encodeToString()` (produces shorter, URL-safe output)
- **Instance lifecycle:** New instance per request → Shared static instance (reuse improves performance and prevents repeated self-seeding)
- **Cookie value length:** ~7 characters (e.g., "0.123456") → ~22 characters (base64-encoded 16 bytes)

None of these changes alter the cookie's semantics or behavior—they preserve the remember-me mechanism while closing the predictability weakness. The cookie is still set with the same name, domain, path, and security attributes (secure, httpOnly).
