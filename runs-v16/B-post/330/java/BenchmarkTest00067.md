## Verdict

Exploitable. Line 90 uses `java.lang.Math.random()` to generate a security-relevant value that becomes a remember-me authentication token. The value's unpredictability is essential to its function - an attacker who can predict the token can impersonate any user. `Math.random()` is a non-cryptographic PRNG with only 48 bits of internal state, making its outputs fully recoverable from a small sample of observed values.

## Source

`java.lang.Math.random()` at line 90 generates the weak random value.

## Fix

**Vulnerable code (lines 89-91):**
```java
// SAST FINDING: CWE-330 (Use of Insufficiently Random Values) - a security-relevant value is drawn from a non-cryptographic PRNG. Sink is the next statement.
double value = java.lang.Math.random();
String rememberMeKey = Double.toString(value).substring(2); // Trim off the 0. at the front.
```

**Fixed code:**

Add to the class as a shared static field (after `private static final long serialVersionUID`):
```java
private static final java.security.SecureRandom SECURE_RANDOM = new java.security.SecureRandom();
```

Replace lines 89-91 with:
```java
// CWE-330: Generate cryptographically secure token for authentication cookie
byte[] randomBytes = new byte[16];
SECURE_RANDOM.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

## Explanation

The fix replaces `Math.random()` with `SecureRandom`, which is Java's cryptographic PRNG. `SecureRandom` generates unpredictable values suitable for authentication tokens and cannot be reverse-engineered from observed outputs. The shared static instance reuses one initialized PRNG across requests, avoiding per-request construction cost and self-seeding overhead. The fix generates 16 bytes (128 bits) of entropy, meeting OWASP ASVS requirements for non-guessable values. `Base64.getUrlEncoder().withoutPadding()` encodes the bytes in a URL-safe format suitable for cookies, replacing the previous approach of converting a double to its decimal representation. The new format eliminates the weak output shape that `Double.toString()` imposes and uses the full entropy of the random source.

## Behaviour changes

The cookie value changes format from a truncated decimal (approximately 15-17 digits, e.g. "123456789012345") to a URL-safe Base64 string (22-24 characters, e.g. "aBc1D2eF3gH4iJkLmNoPqR=="). This format change is a direct consequence of using cryptographic randomness - the previous decimal format was an artifact of converting a double to a string. The new token is longer, which is appropriate for the increased entropy. Existing remember-me cookies created with the old weak generator will no longer match (line 108), so users will be prompted to re-authenticate the first time they visit after deployment. This is the expected and correct behavior when rotating from weak to strong token generation.

