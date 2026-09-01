## Verdict

Exploitable. `Math.random()` returns a 48-bit weak pseudorandom value unsuitable for a remember-me token, which allows an attacker to predict session identifiers.

## Source

Line 74: `java.lang.Math.random()` returns a double drawn from a weak 48-bit linear congruential generator.

## Fix

**Vulnerable code (lines 73-75):**
```java
// SAST FINDING: CWE-330 (Use of Insufficiently Random Values) - a security-relevant value is drawn from a non-cryptographic PRNG. Sink is the next statement.
double value = java.lang.Math.random();
String rememberMeKey = Double.toString(value).substring(2); // Trim off the 0. at the front.
```

**Fixed code:**

Add a class-level field:
```java
private static final java.security.SecureRandom secureRandom = new java.security.SecureRandom();
```

Replace lines 73-75 with:
```java
// Generate cryptographically secure token for remember-me cookie
byte[] randomBytes = new byte[16];
secureRandom.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

## Explanation

`Math.random()` uses `java.util.Random` internally, a 48-bit linear congruential generator with outputs fully recoverable from observed values. The fix replaces it with `SecureRandom`, which sources entropy from the platform's cryptographic randomness provider (`/dev/urandom` on Linux, CNG on Windows). A shared static instance avoids the cost of repeated construction and self-seeding on every request while remaining thread-safe per the Javadoc. The 16-byte (128-bit) value meets OWASP ASVS baseline entropy requirements for non-guessable tokens. Base64 encoding produces a valid string representation with no entropy loss.

## Behaviour changes

- `rememberMeKey` length changes from ~15-16 characters (variable decimal digits from double) to 24 characters (base64 encoding of 16 bytes)
- Entropy increases from ~48 bits to 128 bits
- Token is now cryptographically unpredictable, blocking the core attack vector
- Cookie value, transmission, storage, and validation logic remain unchanged; the fix is localized to token generation only
