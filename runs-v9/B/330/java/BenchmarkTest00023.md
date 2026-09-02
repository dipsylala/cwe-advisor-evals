## Verdict

Exploitable. Confidence: high.

CWE-330 (Use of Insufficiently Random Values), `BenchmarkTest00023.java` line 48.

`java.util.Random` is used to generate the value that becomes a persistent "remember me" authentication token. `java.util.Random` is a 48-bit linear congruential generator; its output is not cryptographically unpredictable, and an attacker who can observe one output (or brute-force the 48-bit state) can predict subsequent values and forge the cookie used to bypass the login check at line 66.

## Source

- **Source**: `new java.util.Random().nextFloat()` — line 48, a non-cryptographic PRNG instantiated inline.
- **Sink**: the same call. Per the loaded CWE-330 guidance, the generator construction itself is the sink; the weakness exists the moment a security-relevant value is drawn from it, independent of any downstream transformation.
- **Flow to the security-relevant use**: the `float` is converted with `Float.toString(rand).substring(2)` (line 49) into `rememberMeKey`, a string of decimal digits. That value is written into the `rememberMe<N>` cookie (lines 76-77, 84) and stored server-side in the session under the same key (line 83). On a later request, `doPost` treats a client-supplied cookie whose value matches the session-stored value as proof of identity (line 66) and grants `foundUser = true`, skipping authentication. The token's unpredictability is exactly what makes it safe to trust, so this is a live path, not a cosmetic-only draw.

## Fix

Vulnerable code (lines 48-49):

```java
// SAST FINDING: CWE-330 (Use of Insufficiently Random Values) - a security-relevant value is drawn from a non-cryptographic PRNG. Sink is the next statement.
float rand = new java.util.Random().nextFloat();
String rememberMeKey = Float.toString(rand).substring(2); // Trim off the 0. at the front.
```

Fixed code:

```java
// Shared instance: SecureRandom is documented safe for concurrent use, and reusing
// it avoids paying provider lookup / self-seeding cost on every request.
private static final SecureRandom SECURE_RANDOM = new SecureRandom();

...

byte[] rememberMeBytes = new byte[16]; // 128 bits, meets the OWASP ASVS non-guessable floor
SECURE_RANDOM.nextBytes(rememberMeBytes);
String rememberMeKey =
        Base64.getUrlEncoder().withoutPadding().encodeToString(rememberMeBytes);
```

Required additional imports:

```java
import java.security.SecureRandom;
import java.util.Base64;
```

`SECURE_RANDOM` is declared once as a `private static final` field on the servlet class (alongside `serialVersionUID`), not constructed per-request, per the language guidance's remediation steps. No library recommendation is needed — `SecureRandom` and `Base64` are both part of the JDK.

## Explanation

The fix replaces the non-cryptographic `java.util.Random` with `java.security.SecureRandom`, the JDK's cryptographic generator, and switches from formatting a single `float` to filling and encoding a byte buffer, which is the mechanism `SecureRandom` exposes for producing token material. `new SecureRandom()` (not `getInstanceStrong()`) is used, per the language guidance, because `getInstanceStrong()` can resolve to a blocking entropy source and this call sits on a request path (`doPost`), where a hang would be a self-inflicted denial of service. Sixteen bytes (128 bits) meets the ASVS floor for a non-guessable value cited in the general guidance. The result is base64url-encoded rather than truncated or reduced through a modulo, so none of the generator's entropy is discarded before the value reaches the cookie. This closes the weakness because the token's unpredictability is now backed by a CSPRNG instead of a 48-bit LCG state that an attacker could recover from a single observed output and use to predict or forge subsequent `rememberMe` tokens.

Because the previously issued cookies were generated from the weak `Random` source, any `rememberMe` tokens already issued to real users remain guessable until they expire or are explicitly revoked; regenerating this code path alone does not invalidate them. That rotation is outside the scope of a source-code change and is called out here per the general guidance's remediation steps.

## Behaviour changes

- **Token format changed**: the original `rememberMeKey` was a variable-length string of ASCII digits (`Float.toString` output with the leading `"0."` trimmed). The fixed value is a fixed-length, 22-character base64url string (alphabet `A-Za-z0-9-_`). This is a necessary consequence of moving off a `float`-shaped weak source to byte-oriented `SecureRandom` output, not an incidental change — the guidance explicitly rejects narrowing or reformatting the new source's output (e.g. via truncation) to preserve the old shape, since that would shrink the keyspace back down.
- **Cookie/session value contents change, not their handling**: `rememberMeKey` is still used exactly as before — as the `Cookie` value (line 77) and as the session attribute value it is compared against (lines 66, 83). Base64url's character set (`A-Za-z0-9-_`) contains no characters excluded from cookie values, so no cookie-encoding or header-injection concern is introduced. Comparison remains a plain string equality check with no parsing of the token's contents elsewhere in this file, so the format change does not alter control flow.
- **No change to**: cookie attributes (`Secure`, `HttpOnly`, domain, path), session storage mechanism, the authentication comparison logic, or any other returned/discarded value at the sink.
- **Not addressed by this change**: rotation of tokens issued by the pre-fix code (see Explanation) — those remain valid and guessable until they expire or are otherwise revoked.
