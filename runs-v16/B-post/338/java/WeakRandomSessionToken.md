## Verdict

exploitable

## Source

The `seed` parameter from the HTTP request (line 13-14: `String seedParam = request.getParameter("seed"); long seed = Long.parseLong(seedParam);`) is attacker-controlled and flows directly into seeding `java.util.Random` on line 17. Session tokens are security-sensitive values used for user authentication and must not be reproducible from attacker-supplied input.

## Fix

**Vulnerable code:**
```java
String seedParam = request.getParameter("seed");
long seed = Long.parseLong(seedParam);

// SAST FINDING: CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)) reported here. Sink is the next statement.
Random random = new Random(seed);

String sessionToken = Long.toHexString(random.nextLong());

response.setHeader("X-Session-Token", sessionToken);
```

**Fixed code:**
```java
// Do not accept seed from request; use SecureRandom for cryptographic operations
SecureRandom secureRandom = new SecureRandom();
byte[] tokenBytes = new byte[8];
secureRandom.nextBytes(tokenBytes);

// Convert bytes to hex string
StringBuilder hex = new StringBuilder();
for (byte b : tokenBytes) {
    hex.append(String.format("%02x", b));
}
String sessionToken = hex.toString();

response.setHeader("X-Session-Token", sessionToken);
```

## Explanation

The original code uses `java.util.Random`, a non-cryptographic PRNG designed for statistical simulation, not security. It is seeded with an attacker-controlled value from the request, making the token entirely predictable: an attacker who controls the seed can reproduce any token. The fix replaces `Random` with `java.security.SecureRandom`, a cryptographically secure random number generator that seeds itself from the operating system's entropy sources (`/dev/urandom` on Unix, `CryptGenRandom` on Windows). `SecureRandom` generates unpredictable values unsuitable for manipulation by an attacker, even if the attacker-supplied seed parameter is removed from the flow. The token is now generated from 8 bytes (64 bits) of cryptographic randomness, independent of any request input.

## Behaviour changes

- **Seed parameter no longer used**: Removing the request parameter's seed is the core security fix. Sessions are no longer reproducible from attacker knowledge. This is an intentional breaking change that is necessary for correct security.
- **SecureRandom initialization**: `SecureRandom()` is initialized without arguments, automatically seeded by the OS. This is the secure-by-default pattern recommended by the Java security guidance and differs from the vulnerable `new Random(seed)` approach.
- **Token generation method unchanged in intent**: The output remains a hex string, preserving the interface with the response header. The token is now 16 hex characters (from 8 bytes) instead of a variable-length hex string from `Long.toHexString()`, which is a minor format change that does not break downstream parsing.

No new dependencies or versions are required. `java.security.SecureRandom` is part of the Java standard library in all supported versions.

Verification: Fixed code compiled successfully with `javac` (Java 8+ syntax confirmed compatible).

