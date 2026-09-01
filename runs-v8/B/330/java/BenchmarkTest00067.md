## Verdict

Exploitable. The vulnerability is confirmed at line 90, where a cryptographically weak random value is generated for use in a security-relevant context (a "remember me" token stored in a persistent cookie and session attribute).

## Source

`java.lang.Math.random()` at line 90, a non-cryptographic pseudo-random number generator unsuitable for security tokens.

## Fix

**Vulnerable code (lines 89–91):**
```java
// SAST FINDING: CWE-330 (Use of Insufficiently Random Values) - a security-relevant value is drawn from a non-cryptographic PRNG. Sink is the next statement.
double value = java.lang.Math.random();
String rememberMeKey = Double.toString(value).substring(2); // Trim off the 0. at the front.
```

**Fixed code:**

Add a shared `SecureRandom` field to the class:
```java
private static final java.security.SecureRandom secureRandom = new java.security.SecureRandom();
```

Replace lines 90–91 with:
```java
// Generate cryptographically secure token (128 bits minimum for non-guessable values)
byte[] tokenBytes = new byte[16];
secureRandom.nextBytes(tokenBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
```

## Explanation

The original code derives a session token from `Math.random()`, a non-cryptographic PRNG with a 48-bit LCG state recoverable from observed output. An attacker observing any issued token can predict all past and future tokens, fully compromising the "remember me" functionality. The fix replaces the weak generator with `SecureRandom`, which uses the platform's cryptographic entropy source. The shared `private static final` instance avoids the construction and self-seeding overhead of creating a fresh `SecureRandom` per request. Bytes are generated via `nextBytes()` and encoded as URL-safe Base64 without padding, producing a token with 128 bits of entropy—the OWASP ASVS minimum for any non-guessable value. The fix preserves the sink's contract: the token is still a string passed to the cookie constructor and session attribute, with no change to error handling or logging.

## Behaviour changes

1. **Token length**: Encoded output changes from a 16-character string (derived from `0.xxxxxxxxxxxxx`) to a 24-character Base64 string (16 bytes → 24 base64 chars without padding). Token comparison remains a string equality check, so this is transparent to the session validation logic at line 108.

2. **Entropy**: Token unpredictability improves from 48 bits to 128 bits, eliminating the guessing attack. This is the intended security improvement and alters no external behavior—the same cookie and session storage paths are used.

3. **No exception handling changes**: `SecureRandom.nextBytes()` does not throw for normal operation; the fixed code carries no new error paths beyond the original.
