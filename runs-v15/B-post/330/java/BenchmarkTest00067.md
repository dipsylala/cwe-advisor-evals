## Verdict
Exploitable. The finding identifies a legitimate security-relevant use of a non-cryptographic PRNG for a session token (remember-me cookie).

## Source
`java.lang.Math.random()` at line 90.

## Fix

**Vulnerable code (lines 90–91):**
```java
double value = java.lang.Math.random();
String rememberMeKey = Double.toString(value).substring(2); // Trim off the 0. at the front.
```

**Fixed code:**

Add a static field to the class (after the `serialVersionUID` declaration):
```java
private static final java.security.SecureRandom random = new java.security.SecureRandom();
```

Replace lines 90–91 in the `doPost` method:
```java
byte[] randomBytes = new byte[16];
random.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

## Explanation
`java.lang.Math.random()` uses a non-cryptographic PRNG (a 48-bit LCG state) recoverable from observed output, making it unsuitable for session tokens. The fix replaces it with a shared `SecureRandom` instance, which provides a cryptographically strong pseudo-random number generator. Generating 16 random bytes (128 bits) meets OWASP ASVS's minimum entropy requirement for non-guessable values. Base64 URL-safe encoding (without padding) provides a safe string representation suitable for cookie values. Reusing a static `SecureRandom` instance avoids per-request provider lookup and self-seeding overhead while remaining safe for concurrent access per its Javadoc contract.

## Behaviour changes
**New imports:** `java.util.Base64` is added for encoding. It is part of the Java standard library (java.base) since Java 8, so no dependency change is required. The `java.security.SecureRandom` class has been in the standard library since Java 1.1.

**Token length and encoding:** The output format changes from a decimal-like string (e.g., "987654321") to a Base64-encoded 16-byte value. This does not break the cookie mechanism; `javax.servlet.http.Cookie` accepts any string value and both the browser and server will transmit and receive it correctly. Existing cookies generated with the weak method will expire after 3 minutes (or when they are replaced), leaving no stale tokens.

**Shared instance initialization:** A static `SecureRandom` is initialized once at class load time. This has negligible overhead and is thread-safe per its Javadoc. If the class is never loaded (e.g., unused servlet), no initialization occurs.
