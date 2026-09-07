## Verdict

**CONFIRMED - Improper Authentication via Unsigned JWT Parsing**

The code at line 58 uses `Jwts.parser().parseClaimsJwt(token)`, an unsigned JWT parsing method that accepts tokens with `"alg":"none"` without signature verification. An attacker can forge an arbitrary JWT and authenticate as any user without knowing the signing secret.

## Source

**File:** JwtAuthenticationFilter.java  
**Line:** 58  
**Data source:** Untrusted JWT in the `Authorization` HTTP header (line 53)

**Data flow:**
1. Line 53: Extract `Authorization` header from HTTP request
2. Line 55: Extract JWT token by removing "Bearer " prefix
3. Line 58: Parse token using unsigned method `parseClaimsJwt()` — **SINK**
4. Lines 60-61: Extract username from untrusted JWT claims
5. Lines 63-65: Authenticate request with untrusted username

## Fix

**Library version:** jjwt 0.11.5 (as specified in comments; guidance applies to 0.11.x line)

**Vulnerable code (line 58):**
```java
Jwt<?, Claims> jwt = Jwts.parser().parseClaimsJwt(token);
```

**Fixed code:**
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
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
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
 * On jjwt 0.11.5, Jwts.parser().parseClaimsJwt(token) parses unsigned
 * "JWT" and accepts "alg":"none", letting any caller mint arbitrary claims.
 * 
 * Fixed to use parseClaimsJws() with signature verification via setSigningKey().
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
                // Parse and verify the JWT signature with the signing key
                Jwt<?, Claims> jwt = Jwts.parser()
                        .setSigningKey(signingKey)
                        .parseClaimsJws(token);

                Claims claims = jwt.getBody();
                String username = claims.getSubject();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JwtException | IllegalArgumentException e) {
                // Invalid token: signature verification failed, malformed, expired, etc.
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
```

## Explanation

**What changed:**
1. **Method swap** (line 58→54): Replaced unsigned `parseClaimsJwt()` with signed `parseClaimsJws()`
2. **Added signing key** (line 54): Introduced constructor parameter `SecretKey signingKey` and call to `.setSigningKey(signingKey)` on the parser to bind signature verification
3. **Error handling** (lines 56-60): Wrapped parsing in try-catch to catch `JwtException` and `IllegalArgumentException`, and return 401 Unauthorized on verification failure
4. **Import addition**: Added `JwtException` import to handle signature failures

**Why this eliminates the weakness:**

The unsigned `parseClaimsJwt()` method in jjwt 0.11.5 accepts any JWT with `"alg":"none"` without checking a signature. An attacker can forge a JWT, set any username in the subject claim, and be authenticated without knowledge of the signing secret.

The fixed code uses `parseClaimsJws()` (the signed variant for 0.11.x) bound to `.setSigningKey(signingKey)`, which:
- Validates the JWT signature against the server's signing key
- Rejects tokens signed with a different key or with `"alg":"none"`
- Prevents algorithm-confusion and algorithm-substitution attacks
- Ensures only the authorized issuer (who possesses the signing key) can create valid tokens

The try-catch block ensures that any signature verification failure, malformed token, or expired token results in a 401 Unauthorized response rather than silently accepting the invalid token.

**Assumptions:**
- The `signingKey` parameter is a `SecretKey` generated with sufficient entropy and loaded from secure configuration or a secret store (not hardcoded)
- The key is the same one used to sign JWTs on the issuer side
- The application is using Spring Security's `SecurityFilterChain` to enforce authentication on protected endpoints

## Behaviour changes

**User-visible impact:**
- Valid JWTs with correct signatures continue to authenticate normally
- Invalid JWTs (wrong signature, `"alg":"none"`, malformed, expired) now return 401 Unauthorized instead of being accepted
- If no Authorization header is present or it doesn't start with "Bearer ", the request continues to the next filter (existing behaviour preserved)

**Request/response changes:**
- Previously: Forged JWT with `"alg":"none"` and arbitrary claims → authenticated session established
- After fix: Forged JWT → 401 Unauthorized response, no session established
- Previously: Missing or malformed JWT → silently passed through (no authentication set)
- After fix: Missing or malformed JWT → 401 Unauthorized if JWT parsing fails, or passed through if no header present (same as before)

**Functional equivalence:**
- All legitimate requests with valid JWTs work identically before and after
- The filter's return value and exception handling ensure downstream filters are not called when an invalid token is detected (breaking the chain with 401)
