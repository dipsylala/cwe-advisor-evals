## Verdict

CWE-330 confirmed. Line 90 uses `java.lang.Math.random()` to generate a security-sensitive token value for a persistent "remember me" authentication cookie. `Math.random()` provides insufficient randomness for security-critical purposes.

## Source

```java
// Line 90 (vulnerable)
double value = java.lang.Math.random();
String rememberMeKey = Double.toString(value).substring(2);
```

The value is subsequently stored in a `rememberMe` cookie (line 120) and the session (line 126) for authentication purposes.

## Fix

Replace `Math.random()` with `SecureRandom`:

```java
java.security.SecureRandom secureRandom = new java.security.SecureRandom();
byte[] randomBytes = new byte[16];
secureRandom.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

Alternatively, use `java.util.UUID`:

```java
String rememberMeKey = java.util.UUID.randomUUID().toString();
```

## Explanation

`Math.random()` is a linear congruential generator designed for non-security applications and offers only 48 bits of internal state. An attacker can predict or brute-force the output, compromising the authentication token.

`SecureRandom` provides cryptographically strong randomness suitable for security tokens. The fix generates 16 random bytes and encodes them as URL-safe Base64 (no padding), producing a strong, compact token. Alternatively, `UUID.randomUUID()` uses `SecureRandom` internally and is simpler for remember-me tokens.

Store the generated value immediately before use to minimize timing windows between generation and cookie assignment, and ensure the cookie is marked `Secure` and `HttpOnly` (already done on lines 121-122).
