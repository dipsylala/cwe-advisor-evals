## Verdict

**Real issue. Fix required.**

CWE-330 finding confirmed: `Math.random()` at line 74 generates session tokens (line 104, cookie value) using a non-cryptographic PRNG. The value is predictable and can be exhaustively guessed by an attacker, allowing forged session persistence.

## Source

**Lines 74-75:**
```java
double value = java.lang.Math.random();
String rememberMeKey = Double.toString(value).substring(2);
```

**Sink: Line 104**
```java
javax.servlet.http.Cookie rememberMe = new javax.servlet.http.Cookie(cookieName, rememberMeKey);
```

The rememberMe cookie is set with the weak value and later compared for session validation (line 92), making it exploitable.

## Fix

Add a static final SecureRandom instance at the class level:
```java
private static final java.security.SecureRandom SECURE_RANDOM = new java.security.SecureRandom();
```

Replace lines 73-75:
```java
// SAST FINDING: CWE-330 (Use of Insufficiently Random Values) - a security-relevant value is drawn from a non-cryptographic PRNG. Sink is the next statement.
double value = java.lang.Math.random();
String rememberMeKey = Double.toString(value).substring(2); // Trim off the 0. at the front.
```

With:
```java
// Generate cryptographically strong random token for session persistence
byte[] randomBytes = new byte[16]; // 128 bits of entropy
SECURE_RANDOM.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

## Explanation

The fix replaces `Math.random()` (a 48-bit LCG with predictable state) with `SecureRandom` generating 16 bytes (128 bits) of cryptographically strong randomness. The entropy is encoded as URL-safe Base64 without padding, suitable for cookie values.

`Math.random()` can be predicted by observing a single output value; `SecureRandom.nextBytes()` cannot. The static instance reuses one PRNG across requests, avoiding the cost of initialization and self-seeding on every token generation while remaining thread-safe per Javadoc.

This closes the predictability gap: the cookie value is no longer guessable and session forgery is no longer feasible.

## Behaviour changes

- Token length increases from ~15 characters (decimal double representation) to ~24 characters (Base64 of 16 bytes), improving entropy density.
- Token generation now draws from the system's entropy pool (blocking briefly if needed during class initialization, never on request paths).
- Session token format changes from decimal to Base64, requiring session store rotation: existing "remember me" cookies will not validate against the new token format. No action required; expired tokens naturally fall away.
- No functional impact to the session workflow: authentication and cookie comparison logic remain unchanged. Only the token generation source and format change.
