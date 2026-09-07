## Verdict

Exploitable. The code uses `java.util.Random`, a non-cryptographic PRNG, to generate a security-relevant value: a session token used in a remember-me cookie. The weak generator's 48-bit LCG state is recoverable from observed output, allowing an attacker to forge valid session tokens and bypass authentication.

## Source

Line 48: `float rand = new java.util.Random().nextFloat();` - weak PRNG source
Line 49: `String rememberMeKey = Float.toString(rand).substring(2);` - derivation and use as cookie value

## Fix

**Vulnerable code:**
```java
// Lines 48-49
float rand = new java.util.Random().nextFloat();
String rememberMeKey = Float.toString(rand).substring(2); // Trim off the 0. at the front.
```

**Fixed code:**
```java
// Add at class level, after serialVersionUID:
private static final java.security.SecureRandom secureRandom = new java.security.SecureRandom();

// Replace lines 48-49 in doPost:
byte[] randomBytes = new byte[16];
secureRandom.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

## Explanation

The fix replaces the weak `java.util.Random` with `java.security.SecureRandom`, which is cryptographically secure and suitable for security-relevant values. A shared static instance avoids the cost of per-request initialization and self-seeding while remaining thread-safe. The code generates 16 bytes (128 bits), meeting OWASP ASVS requirements for non-guessable tokens, and encodes them with URL-safe Base64 without padding. This ensures the remember-me token has full cryptographic entropy and cannot be forged by observing other tokens. The change is minimal and preserves the cookie's string representation for the session attribute and cookie value.

## Behaviour changes

1. **Added static field**: A `secureRandom` instance is created once at class initialization instead of per-request; no functional change to the servlet's contract, only one-time setup cost.
2. **Changed entropy source**: From 48-bit predictable LCG to 128-bit cryptographically random bytes; the token is now non-guessable.
3. **Changed encoding**: From `Float.toString().substring()` (produces ~7 characters) to Base64 URL-safe encoding of 16 bytes (produces 22 characters); both are valid string representations for cookies, but the fixed version is longer and properly random.
4. **No API changes**: `rememberMeKey` is still a `String` and flows to the same cookie and session attribute uses; no changes needed downstream.
