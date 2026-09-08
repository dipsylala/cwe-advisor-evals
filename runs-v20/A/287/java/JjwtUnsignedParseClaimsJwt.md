## Verdict

Confirmed. `Jwts.parser().parseClaimsJwt(token)` (jjwt 0.11.5) parses the unsigned "JWT" compact form: it accepts a token whose header carries `"alg":"none"` (or any unsigned/plaintext JWT) and never checks a MAC or signature. A caller can base64url-encode an arbitrary header/claims pair, omit the signature segment, and be authenticated as any username, including privileged accounts.

## Source

The bearer token from the `Authorization` request header (`JwtAuthenticationFilter.doFilterInternal`, line 53-55) is attacker-controlled input. It flows unmodified into `Jwts.parser().parseClaimsJwt(token)` at line 58, whose returned claims (`claims.getSubject()`) are then used to build the `Authentication` placed on the `SecurityContextHolder` - so an unverified claim set is trusted directly into the authentication decision.

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
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Key;
import java.util.Collections;

/**
 * Authenticates incoming requests from a bearer JWT on the Authorization header.
 *
 * The token is parsed as a signed JWS and its signature is verified against
 * signingKey before any claim is trusted. A token that fails verification -
 * a bad signature, an "alg":"none" / unsigned token, an expired token, or a
 * malformed compact string - is rejected and the request proceeds
 * unauthenticated.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final Key signingKey;

    public JwtAuthenticationFilter(Key signingKey) {
        this.signingKey = signingKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader(AUTH_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length());

            try {
                Jws<Claims> jwt = Jwts.parserBuilder()
                        .setSigningKey(signingKey)
                        .build()
                        .parseClaimsJws(token);

                Claims claims = jwt.getBody();
                String username = claims.getSubject();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JwtException | IllegalArgumentException e) {
                // Signature verification failed, the token was unsigned/malformed,
                // or it was expired. Leave the SecurityContext unauthenticated so
                // downstream authorization rejects the request.
            }
        }

        chain.doFilter(request, response);
    }
}
```

## Explanation

`parseClaimsJwt` is jjwt's API for the plaintext/unsigned "JWT" compact form (three or two segments with an empty signature and no cryptographic check); it is not the API for a signed token, so calling it on attacker input is a no-op on trust regardless of what the header claims. Switching to `Jwts.parserBuilder().setSigningKey(signingKey).build().parseClaimsJws(token)` selects the JWS parser, which requires the compact string to carry a signature and verifies it against `signingKey` (HMAC or asymmetric, per whatever key material the application already provisions for issuing tokens) before returning any claims; a token with `"alg":"none"`, a stripped signature, or a signature computed with the wrong key throws `SignatureException`/`MalformedJwtException` (both `JwtException`) and is caught, leaving the request unauthenticated instead of impersonated. The signing key is taken as a constructor dependency rather than hard-coded, so the same key used to issue tokens is the one used to verify them, and it can be rotated or sourced from a secrets manager without touching this class. The `catch` also covers `ExpiredJwtException`, so an expired-but-otherwise-valid token is rejected rather than accepted, which the original code never checked either.
