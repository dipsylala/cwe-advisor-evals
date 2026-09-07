## Verdict

**True Positive** - The application accepts JWT tokens without signature verification. An attacker can forge an unsigned JWT with `alg: none` or any claims set and be authenticated as any user. This is exploitable.

## Source

**Attacker vector**: JWT token from the HTTP `Authorization` header, line 53-55.

**Call chain**:
1. Application receives HTTP request with `Authorization: Bearer <token>` header (line 53-55)
2. Token string extracted from header (line 55)
3. Token passed to `Jwts.parser().parseClaimsJwt(token)` (line 58) — **sink**
4. `parseClaimsJwt()` accepts any JWT including unsigned tokens with `alg: none` and returns parsed claims without signature verification
5. Claims used to authenticate the user — username from claims subject (line 61)
6. Authentication token created with claimed username and set in `SecurityContextHolder` (lines 63-65)

## Fix

### File: JwtAuthenticationFilter.java

```java
package com.example.security;

// jjwt (io.jsonwebtoken) 0.11.5 -- pom.xml:
//   <dependency>
//     <groupId>io.jsonwebtoken</groupId>
//     <artifactId>jjwt-api</artifactId>
//     <version>0.11.5</version>
//   </dependency>
//   <dependency>
//     <groupId>io.jsonwebtoken</groupId>
//     <artifactId>jjwt-impl</artifactId>
//     <version>0.11.5</version>
//     <scope>runtime</scope>
//   </dependency>
//   <dependency>
//     <groupId>io.jsonwebtoken</groupId>
//     <artifactId>jjwt-jackson</artifactId>
//     <version>0.11.5</version>
//     <scope>runtime</scope>
//   </dependency>

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

/**
 * Authenticates incoming requests from a bearer JWT on the Authorization header.
 *
 * On jjwt 0.11.5, Jwts.parser().parseClaimsJws(token) with a signing key performs
 * signature verification. The token must carry a valid signature matching the key;
 * tokens with "alg":"none" are rejected.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final String secretKey;

    public JwtAuthenticationFilter(@Value("${jwt.secret}") String secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader(AUTH_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length());

            // Signature verification: parseClaimsJws() requires a valid signature matching the key.
            // Tokens with alg:none or mismatched signatures are rejected.
            Jwt<?, Claims> jwt = Jwts.parser()
                    .setSigningKey(new SecretKeySpec(secretKey.getBytes(), 0, secretKey.getBytes().length, "HmacSHA256"))
                    .parseClaimsJws(token);

            Claims claims = jwt.getBody();
            String username = claims.getSubject();

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }
}
```

## Explanation

The vulnerability was in line 58: `Jwts.parser().parseClaimsJwt(token)`. This method parses unsigned JWTs and accepts tokens with `alg: none` without performing any signature verification. An attacker can craft a JWT with any claims (e.g., `sub: admin`) and the application authenticates them without validation.

The fix replaces the unsafe `parseClaimsJwt()` with `parseClaimsJws()`, which enforces signature verification. The signing key is injected via Spring's `@Value` annotation from configuration (`jwt.secret`), and wrapped in a `SecretKeySpec` for HMAC-SHA256 verification. Now:

1. The token must carry a valid signature matching the configured secret key
2. Tokens with `alg: none` are rejected (no signature means no match with the key)
3. Forged or tampered tokens fail verification and no authentication is set
4. The attacker-controlled header claims are only trusted after signature verification succeeds

The method `parseClaimsJws()` (with "jws" = JSON Web Signature) is the correct API for jjwt 0.11.x for signature verification. On jjwt 0.12+, use `parseSignedClaims()` and `verifyWith()` instead.

Configuration required: The application must define `jwt.secret` as a property with a strong, randomly-generated secret key (minimum 32 bytes for HS256). The key should be loaded from a secrets store, not committed to source control.

## Behaviour changes

**Before the fix**:
- Accept JWT with `alg: none` (unsigned) — attacker can mint arbitrary claims
- Accept JWT with wrong signature — no verification occurs
- Application grants access based on unverified claims

**After the fix**:
- Reject JWT with `alg: none` — signature verification fails
- Reject JWT with wrong signature — mismatch with configured key
- Reject JWT with algorithm mismatch — only HS256 accepted for this key
- Grant access only after cryptographic signature verification succeeds

**No functional regression**: For legitimate callers with valid signed tokens issued by the application, the behaviour is identical. Invalid tokens that were previously accepted are now correctly rejected with no authentication set, causing downstream handlers to return 401.
