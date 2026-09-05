## Verdict

Exploitable. Line 48 uses `java.util.Random().nextFloat()` to generate a security-relevant token for a "remember me" cookie. The 48-bit LCG state of `java.util.Random` is cryptographically weak and can be recovered from observed output, allowing an attacker to forge or predict session tokens and impersonate users.

## Source

Line 48: `float rand = new java.util.Random().nextFloat();`

The weak random value is converted to a string (line 49) and used as the value for a persistent "remember me" cookie (lines 76-84) and session attribute (line 83).

## Fix

**Vulnerable code (lines 48-49):**

```java
float rand = new java.util.Random().nextFloat();
String rememberMeKey = Float.toString(rand).substring(2);
```

**Fixed code:**

Add a class-level `SecureRandom` instance (insert after line 30):

```java
private static final java.security.SecureRandom secureRandom = new java.security.SecureRandom();
```

Replace lines 48-49 with:

```java
byte[] randomBytes = new byte[16];
secureRandom.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

## Explanation

The fix replaces `java.util.Random` with `SecureRandom`, which is the platform's cryptographic PRNG. It generates 16 bytes (128 bits) of cryptographically strong randomness, meeting OWASP ASVS requirements for session tokens. The bytes are encoded as URL-safe Base64 without padding to produce a safe string representation for cookie and session storage. Using a shared `private static final` instance avoids the overhead of provider lookup and self-seeding on each request, which was the original reason `java.util.Random` appeared on this code path. `java.security.SecureRandom` is thread-safe and suitable for concurrent use in a servlet context.

## Behaviour changes

- **Randomness source**: Changed from 48-bit LCG (`java.util.Random`) to cryptographically strong PRNG (`SecureRandom`). This eliminates predictability and is the core security fix.
- **Output format**: Changed from a truncated decimal float string (e.g., "12345678") to Base64-encoded bytes (e.g., "A1b2C3d4E5f6G7h8IQ=="). The token is now 24 characters instead of ~7, providing 128 bits of entropy instead of ~17 bits.
- **Token length invariant**: The original code produced variable-length tokens depending on the float's string representation; the fixed code always produces exactly 24 characters (16 bytes Base64-encoded without padding).

None of these changes break the sink contract: the cookie and session still receive a string token, the string is still suitable for transmission and storage, and the flow remains identical from a caller's perspective.
