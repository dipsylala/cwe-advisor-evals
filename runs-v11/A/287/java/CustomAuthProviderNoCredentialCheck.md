## Verdict

CWE-287 vulnerability confirmed. The authenticate method returns a successful authentication token without verifying the provided credentials against the stored password hash.

## Source

File: `evals/cases/287/java/CustomAuthProviderNoCredentialCheck/CustomAuthenticationProvider.java`

The vulnerability is at line 34. The code loads UserDetails by username and immediately returns an authenticated token without validating the provided password:

```java
UserDetails userDetails = userDetailsService.loadUserByUsername(username);
if (userDetails == null) {
    throw new UsernameNotFoundException("No user found with username: " + username);
}

return new UsernamePasswordAuthenticationToken(userDetails, credentials, userDetails.getAuthorities());
```

The `credentials` object (the plaintext password from the login request) is extracted at line 26 but never compared against the stored password hash in `userDetails`.

## Fix

Add password validation before returning the authenticated token. Inject a `PasswordEncoder` and use it to verify the credentials:

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

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (userDetails == null) {
            throw new UsernameNotFoundException("No user found with username: " + username);
        }

        String rawPassword = credentials != null ? credentials.toString() : "";
        String encodedPassword = userDetails.getPassword();

        if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
            throw new BadCredentialsException("Invalid credentials for user: " + username);
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

The original code violates CWE-287 by performing authentication without credential verification. Returning an authenticated token after only checking username existence bypasses the entire password check.

**Key changes:**

1. **Inject PasswordEncoder**: Add `PasswordEncoder` as a constructor dependency—this is Spring's standard mechanism for secure password comparison.

2. **Extract plaintext password**: Convert the credentials object to a string, handling the case where it might be null.

3. **Validate password**: Call `passwordEncoder.matches(rawPassword, encodedPassword)` to safely compare the provided plaintext password against the stored encoded hash. The `matches()` method uses constant-time comparison to prevent timing attacks.

4. **Throw on mismatch**: Raise `BadCredentialsException` if the password does not match, preventing authentication success.

5. **Return token only after verification**: Line 34 (the original vulnerable line) now executes only after successful password validation.

The `PasswordEncoder` is configured as a Spring bean (typically `BCryptPasswordEncoder` or `DelegatingPasswordEncoder` in Spring Security) and handles secure hashing and timing-safe comparison. This ensures authentication cannot succeed without a correct password.
