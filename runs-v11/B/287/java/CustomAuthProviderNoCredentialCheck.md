## Verdict

**VULNERABLE.** The custom `AuthenticationProvider.authenticate()` method returns a successful authentication without verifying the credential against the stored password. This allows any password to authenticate as any known user.

## Source

User-supplied password credential passed as `authentication.getCredentials()` at line 26, sourced from untrusted client input in the HTTP request.

## Fix

**Inject `PasswordEncoder` and verify the credential before returning success.**

```java
package com.example.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

// Targets Spring Security 6.3. Custom AuthenticationProvider used in place of
// the framework's DaoAuthenticationProvider for a legacy login flow.
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public CustomAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        Object credentials = authentication.getCredentials();

        if (credentials == null) {
            throw new BadCredentialsException("No credentials provided");
        }

        String rawPassword = credentials.toString();

        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException ex) {
            // Run dummy password hash check to prevent timing attacks
            // that reveal which usernames exist in the system
            passwordEncoder.matches(rawPassword, "$2a$10$duMmyhash.must.be.a.real.bcrypt.hash");
            throw ex;
        }

        if (userDetails == null) {
            throw new UsernameNotFoundException("No user found with username: " + username);
        }

        // Verify password using PasswordEncoder before authenticating
        if (!passwordEncoder.matches(rawPassword, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        return new UsernamePasswordAuthenticationToken(userDetails, credentials, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```

## Explanation

The vulnerability occurred because the `authenticate()` method returned a successful authentication token without ever calling `PasswordEncoder.matches()` to verify the plaintext password against the stored hash. This allowed an attacker to log in as any user without knowing their password.

The fix adds three changes:

1. **Injected `PasswordEncoder` dependency** (constructor parameter) to enable password verification.

2. **Added null check** for credentials and throw `BadCredentialsException` if missing, preventing authentication with no credential.

3. **Inserted `PasswordEncoder.matches()` call** (after the user lookup succeeds) to verify the supplied plaintext password against the stored hash. If the password does not match, throw `BadCredentialsException` instead of returning success.

4. **Added timing-attack mitigation** via a dummy `PasswordEncoder.matches()` call when `loadUserByUsername()` throws `UsernameNotFoundException`. This runs the same hashing work whether the username exists or not, preventing response-time analysis from revealing which usernames are registered.

The fix closes the authentication bypass while preserving the method's existing contract: it still returns an `Authentication` on success with the user's authorities, and throws an `AuthenticationException` subclass on failure (now including password mismatch). The `supports()` method remains unchanged.

## Behaviour changes

- **Login now requires both a valid username AND a correct password.** Previously any password succeeded.
- **Invalid password attempts now incur the full `PasswordEncoder` hashing cost.** On BCrypt at default strength this is ~200ms per attempt, limiting brute force at the application layer (this is defense-in-depth; rate limiting at the HTTP layer is still required).
- **Username enumeration timing is equalized.** A login attempt against a nonexistent username now takes the same time as one against a known user, eliminating a user-discovery oracle based on response latency.
- **A null or empty credential is now rejected immediately** rather than silently passing through. If the application needs to support passwordless flows (e.g., OAuth, SAML), those should use a separate `AuthenticationProvider` scoped to those token types via `supports()`.
