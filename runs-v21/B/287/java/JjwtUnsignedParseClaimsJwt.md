## Verdict

Exploitable.

## Source

The `token` string extracted from the HTTP `Authorization` header at line 55.

## Fix

### File: JwtAuthenticationFilter.java

```java
package com.example.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

/**
 * Authenticates incoming requests from a bearer JWT on the Authorization header.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    
    private final SecretKey signingKey;

    public JwtAuthenticationFilter(SecretKey signingKey) {
        this.signingKey = signingKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader(AUTH_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length());

            try {
                // Parse JWT with signature verification using the configured signing key
                Jwt<?, Claims> jwt = Jwts.parser()
                    .setSigningKey(signingKey)
                    .parseClaimsJws(token);

                Claims claims = jwt.getBody();
                String username = claims.getSubject();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JwtException e) {
                // Invalid or expired token - do not authenticate
                SecurityContextHolder.clearContext();
            }
        }

        chain.doFilter(request, response);
    }
}
```

## Explanation

The vulnerability on line 58 uses `Jwts.parser().parseClaimsJwt(token)`, which is an unsigned JWT parser that accepts any token with an `alg: none` header without verifying a signature. This allows attackers to forge arbitrary JWT tokens and authenticate as any user. The fix replaces `parseClaimsJwt()` with `parseClaimsJws()` and binds it to a cryptographic verification key via `setSigningKey()`. This ensures the JWT signature is verified before accepting any claims. The fix also adds exception handling to catch `JwtException` (raised on invalid, expired, or tampered tokens) and clears the security context to prevent authentication. The signing key is injected via constructor, ensuring it comes from configuration rather than being hardcoded, and allowing it to be rotated without code changes.

## Behaviour changes

- Added constructor parameter `SecretKey signingKey` for dependency injection of the verification key. This is necessary to verify the JWT signature and breaks the exploit.
- Changed `parseClaimsJwt(token)` to `Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token)`. This closes the signature-bypass vulnerability.
- Added try-catch block around JWT parsing to catch `JwtException`. On error, the security context is cleared so no authentication is granted. The filter then continues to the next filter in the chain (line 68 `chain.doFilter(...)`), allowing the application to return a 401 response or handle the unauthenticated request according to its security policy. The original code had no error handling and would throw an exception, potentially exposing an error message; the fixed code silently rejects invalid tokens.
- Added import for `io.jsonwebtoken.JwtException`.
- Added import for `javax.crypto.SecretKey`.
- Removed the comment block describing the vulnerability, as the fixed code no longer exhibits it.

## Verification

Java syntax validated by static analysis of imports and method calls against jjwt 0.11.5 and Spring Security APIs. All methods used exist in the specified versions:
- `Jwts.parser()` returns `JwtParser`
- `JwtParser.setSigningKey(SecretKey key)` is available in jjwt 0.11.5
- `JwtParser.parseClaimsJws(String token)` is available in jjwt 0.11.5
- `JwtException` is available in jjwt-api 0.11.5
- `SecretKey` is from `javax.crypto` (Java standard library)
- Spring Security methods: `UsernamePasswordAuthenticationToken`, `SecurityContextHolder.getContext().setAuthentication()`, `SecurityContextHolder.clearContext()` are all standard APIs in Spring Security

Code structure matches the original, preserving filter logic and method signatures.

## Assumptions

- The signing key is injected at runtime by the Spring application context (via constructor dependency injection). The key must be a `SecretKey` generated with sufficient entropy (e.g., via `Jwts.SIG.HS256.key().build()` for HMAC-SHA256 algorithms) and loaded from configuration or a secret store, not hardcoded in the application.
- The key is the same key used to sign the tokens on the authentication/token-issue endpoint. If asymmetric algorithms (RS256, ES256, etc.) are used, the type should be changed to `PublicKey`.
- The application's error handling and security filter chain configuration will handle `JwtException` appropriately when the catch block clears the context and continues to the next filter.
