## Verdict

Exploitable. A weak non-cryptographic PRNG is used to generate an authentication token (remember-me cookie), allowing an attacker to predict valid credentials.

## Source

Line 48: `new java.util.Random().nextFloat()` - `java.util.Random` is a non-cryptographic PRNG with ~48-bit state, unsuitable for security-relevant values.

The output is converted to a string (line 49) and used as a remember-me authentication token (lines 77, 83). An attacker observing the token can recover the PRNG state and predict future tokens, defeating the authentication mechanism.

## Fix

**Vulnerable code (lines 48-49):**
```java
float rand = new java.util.Random().nextFloat();
String rememberMeKey = Float.toString(rand).substring(2); // Trim off the 0. at the front.
```

**Fixed code:**
```java
java.security.SecureRandom random = new java.security.SecureRandom();
byte[] randomBytes = new byte[16]; // 128 bits of entropy
random.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

## Explanation

Replace `java.util.Random` with `java.security.SecureRandom` to generate cryptographically strong random values. The fixed code generates 16 bytes (128 bits) of entropy, meeting OWASP ASVS requirements for non-guessable tokens, then encodes it in URL-safe Base64 format for use as a cookie value. `SecureRandom` provides the platform's CSPRNG; creating a fresh instance per request is acceptable for non-high-frequency token generation like remember-me. The entropy source is now unpredictable and resistant to state recovery, closing the vulnerability.

## Behaviour changes

**Token format change**: The original code produces a decimal string (e.g., "23456789"); the fixed code produces Base64 (e.g., "aBcD1234..."). The token length increases from ~1-2 characters to ~24 characters. This is a safe change because the token is opaque to the application — it is only compared for equality and persisted in the cookie/session, so the format change introduces no functional regression.

**Performance**: Creating a `SecureRandom` instance per request adds minimal overhead for token generation on a non-critical path (remember-me is typically called once per session lifetime). No optimization needed unless profiling shows contention.

**No other behavior changes**: The token still satisfies the sink contract — it is a string usable as a cookie value and session attribute, and the comparison logic at line 66 (`cookie.getValue().equals(...)`) is unaffected.
