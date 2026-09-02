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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

/**
 * Authenticates incoming requests from a bearer JWT on the Authorization header.
 *
 * On jjwt 0.11.5, Jwts.parser().parseClaimsJwt(token) parses the unsigned
 * "JWT" compact form: it accepts a token with an "alg":"none" header and
 * never checks a signature, so any caller can mint an arbitrary claims set
 * and be authenticated as any user.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader(AUTH_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length());

            // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
            Jwt<?, Claims> jwt = Jwts.parser().parseClaimsJwt(token);

            Claims claims = jwt.getBody();
            String username = claims.getSubject();

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }
}
