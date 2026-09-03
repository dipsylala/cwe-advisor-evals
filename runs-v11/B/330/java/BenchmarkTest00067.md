## Verdict

VULNERABLE. `Math.random()` is a non-cryptographic PRNG that generates authentication tokens. An attacker can predict the values it produces and forge "remember me" cookies to impersonate users.

## Source

**File**: evals/cases/330/java/BenchmarkTest00067/BenchmarkTest00067.java  
**Line**: 90  
**Vulnerable Code**:
```java
double value = java.lang.Math.random();
String rememberMeKey = Double.toString(value).substring(2);
```

**Data Flow**:
The output of `Math.random()` is converted to a decimal string, trimmed to remove the "0." prefix, and used directly as the value of an HTTP cookie (`rememberMe`) to track user sessions. The same value is stored in the session attribute. On subsequent requests, the code verifies the cookie value matches the stored session value to grant access.

Math.random() produces a 48-bit LCG state, recoverable from a single observed output. An attacker who observes one token can predict all future tokens.

## Fix

**Add static SecureRandom field** at the class level:
```java
private static final java.security.SecureRandom secureRandom = new java.security.SecureRandom();
```

**Replace vulnerable code** at lines 89-91:
```java
// OLD:
// SAST FINDING: CWE-330 (Use of Insufficiently Random Values) - a security-relevant value is drawn from a non-cryptographic PRNG. Sink is the next statement.
double value = java.lang.Math.random();
String rememberMeKey = Double.toString(value).substring(2); // Trim off the 0. at the front.

// NEW:
byte[] randomBytes = new byte[16]; // 128 bits
secureRandom.nextBytes(randomBytes);
String rememberMeKey = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

## Explanation

Math.random() is unsuitable for security-relevant values. Its 48-bit LCG state is recoverable from observed output and fully predictable; changing the seed or the output's shape (string conversion, truncation) changes only how it looks, not its entropy.

SecureRandom generates cryptographically strong random bytes from the platform's entropy source. A 128-bit token meets OWASP ASVS requirements for non-guessable values used in authentication. Base64 URL-safe encoding without padding is suitable for HTTP cookies and matches the original string representation.

The static instance avoids repeated construction and self-seeding costs on every request. SecureRandom is thread-safe, so multiple concurrent requests reuse the same field without contention.

## Behaviour changes

- Token length changes from ~15 characters (decimal representation of 0.X) to 22 characters (Base64 of 16 bytes).
- Token format changes from decimal (0-9) to Base64 URL-safe alphabet (A-Za-z0-9-_).
- Token entropy increases from ~48 bits (predictable) to 128 bits (unpredictable).
- Existing "remember me" cookies become invalid after deployment (the comparison will fail). Users must re-authenticate once.
