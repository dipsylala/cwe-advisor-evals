## Verdict

**Confirmed**. The code at line 74 uses `java.lang.Math.random()`, a non-cryptographic PRNG, to generate a remember-me cookie token. This is a direct instance of CWE-330: the unpredictability of the token is security-critical (session resumption without authentication), and Math.random() supplies only 48 bits of effective entropy as a Java LCG. The value flows directly to cookie creation and session storage with no intervening validation or constraint that would limit its reachability.

## Source

Line 74: `double value = java.lang.Math.random();`

Line 75 transforms this value via `Double.toString(value).substring(2)`, which encodes the 48-bit state as a decimal fraction string; this transformation neither adds entropy nor limits the attacker's ability to predict the token from seed recovery.

## Fix

Add a static SecureRandom field to the class:

```java
private static final java.security.SecureRandom secureRandom = new java.security.SecureRandom();
```

Replace lines 74–75 in the `doPost` method with:

```java
byte[] randomBytes = new byte[16];
secureRandom.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

## Explanation

`java.security.SecureRandom` provides cryptographically strong randomness suitable for tokens. `new SecureRandom()` (not `getInstanceStrong()`) is the correct choice here because this code runs in a request handler and must not block on entropy; `getInstanceStrong()` can hang on Linux when reading `/dev/random`. The byte array is sized to 16 bytes (128 bits), meeting OWASP ASVS and CWE-330 guidance for non-guessable tokens. Base64 URL-safe encoding without padding matches typical cookie value formats and provides a valid web-safe string representation. A shared static instance is thread-safe per Javadoc and avoids the per-request cost of provider lookup and seeding.

## Behaviour changes

- The remember-me token is now cryptographically random and unpredictable.
- Token length will increase from ~13 characters (decimal digits of a double) to 24 characters (base64-encoded 16 bytes).
- Previously issued tokens (from the weak generator) remain valid until session expiry; no rotation is performed here, though the guidance recommends invalidating existing sessions after deployment to force reauthentication and discard guessable tokens.
