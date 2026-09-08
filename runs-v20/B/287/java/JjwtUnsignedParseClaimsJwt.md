## Verdict

Confirmed. `JwtAuthenticationFilter.doFilterInternal` authenticates every request whose bearer token parses with `Jwts.parser().parseClaimsJwt(token)`. On jjwt 0.11.5 that call parses the unsigned "JWT" compact serialization (an `alg: none` header) and never checks a cryptographic signature. An attacker who crafts a base64url-encoded header/payload/empty-signature triplet with any `sub` claim they choose is authenticated as that user, with no server-held secret involved at any point.

## Source

`request.getHeader("Authorization")` - the bearer token is taken verbatim from an attacker-controlled HTTP header.

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
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
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
 *
 * Tokens are verified with Jwts.parserBuilder().setSigningKey(...).build().parseClaimsJws(token),
 * which requires and checks an HMAC signature against a server-held key. An unsigned or
 * mismatched-signature token is rejected before any claim is trusted.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final SecretKey signingKey;

    public JwtAuthenticationFilter(@Value("${jwt.signing-key}") String base64EncodedSigningKey) {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64EncodedSigningKey));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader(AUTH_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length());

            Jws<Claims> jwt = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
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

The sink was `Jwts.parser().parseClaimsJwt(token)`, which on jjwt 0.11.5 parses the unsigned JWT form and returns a populated `Jwt<?, Claims>` for any well-formed `header.payload.` triplet regardless of what the header's `alg` claims or what the payload contains - there is no key involved and nothing to verify. The fix replaces it with `Jwts.parserBuilder().setSigningKey(signingKey).build().parseClaimsJws(token)`, the 0.11.x signed-parsing entry point named in the loaded Java guidance for this exact library version. `parseClaimsJws` requires the token to carry an HMAC signature and recomputes it against `signingKey`; a token with `alg: none`, a stripped signature, or a signature produced with any other key throws `UnsupportedJwtException` or `SignatureException` (both unchecked `JwtException` subtypes, matching the original code's total absence of a catch block, so failure propagates the same way it already did for a malformed token). The call's return type changes from `Jwt<?, Claims>` to `Jws<Claims>`, which still exposes `getBody()` returning `Claims`, so the rest of the method - `claims.getSubject()` and the downstream `SecurityContextHolder` population - is unchanged; the identity placed into the security context is now backed by a value the server has cryptographically verified rather than one an attacker supplied outright.

Verification requires a key, which the unsigned path never needed, so the filter gained a constructor that takes a base64-encoded key material string (intended to be wired from configuration, e.g. a Spring `@Value("${jwt.signing-key}")` property backed by an externalized secret store, never a literal in source) and turns it into a `SecretKey` via `Keys.hmacShaKeyFor(Decoders.BASE64.decode(...))` - both from `jjwt-api`, the dependency already on the classpath. This mirrors the guidance's instruction to generate signing keys with sufficient entropy and load them from configuration rather than hardcoding a string; the actual secret value is an operational deployment concern outside this file's scope, and the key must be the same one used to sign tokens on issuance for legitimate logins to keep working.

**Verification performed**: compiled the fixed file with `javac` against the real `jjwt-api-0.11.5.jar` (the exact version pinned in the file's own dependency comment), `spring-security-core-5.8.16.jar`, `spring-web-5.3.34.jar`, `spring-core-5.3.34.jar`, `spring-beans-5.3.7.jar`, `spring-context-5.3.7.jar`, and `javax.servlet-api-4.0.1.jar` resolved from the local Maven repository. The file compiled with zero errors and zero warnings, confirming `Jwts.parserBuilder()`, `JwtParserBuilder.setSigningKey(Key)`, `JwtParser.parseClaimsJws(String)`, `Jws<Claims>.getBody()`, `Keys.hmacShaKeyFor(byte[])`, and `Decoders.BASE64.decode(String)` all exist with the signatures used, and that `Jws<Claims>` satisfies every downstream use the original `Jwt<?, Claims>` result was put to.

## Behaviour changes

- The class's implicit default (no-arg) constructor is replaced by a one-argument constructor taking the base64-encoded signing key. Whatever currently constructs `JwtAuthenticationFilter` (a `SecurityConfig` `@Bean` method or manual `new JwtAuthenticationFilter()` call, not present in this file) must be updated to supply that key from configuration - this is a required follow-up outside this file's scope, not an optional one, since verification cannot happen without a key.
- A request bearing a token that is well-formed but unsigned, signed with the wrong key, or otherwise fails signature verification now throws (`UnsupportedJwtException` / `SignatureException` / `MalformedJwtException`, all unchecked) instead of being accepted and authenticated. This is the intended effect of the fix: such a request was previously (incorrectly) authenticated and now is not. Neither the original code nor the fix catches this exception inside the filter, so its propagation behaviour (letting the container's default error handling take over) is unchanged from how the original already handled a malformed unsigned token - only the set of inputs that trigger it has grown to include forged/unsigned tokens.
- A token that was legitimately issued by the real signer will continue to authenticate exactly as before, provided the filter is wired with the matching signing key.
