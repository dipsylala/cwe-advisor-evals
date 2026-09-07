## Verdict

The custom `AuthenticationProvider` returns a successful `Authentication` object without verifying the submitted credential against the stored password hash. An attacker can authenticate as any user by providing any value as the password, bypassing authentication entirely.

## Source

**Vulnerable Sink (Line 34):**
```
return new UsernamePasswordAuthenticationToken(userDetails, credentials, userDetails.getAuthorities());
```

**Data Flow:**
- Line 25-26: Username and credentials (password) extracted from `Authentication` request object
- Line 28: User details loaded from `UserDetailsService` by username
- Line 29-31: Null check on user (though `loadUserByUsername` typically throws `UsernameNotFoundException`)
- **Line 34: Authentication success returned without calling `passwordEncoder.matches()`**

The credential value from the request (`credentials` variable) is never compared against the stored password hash (`userDetails.getPassword()`). Any password string allows authentication.

## Fix

### File: CustomAuthenticationProvider.java

```java
package com.example.security;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.AuthenticationProvider;
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
    // Dummy BCrypt hash for timing attack protection (cost 10, strength matching default BCryptPasswordEncoder)
    private static final String DUMMY_PASSWORD_HASH = "$2a$10$6DdHh.9Gg6V5F1.5L2K9lOE6Y0b0dG9x.4L5m6N7o8P9q0r1S2t3U";

    public CustomAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        Object credentials = authentication.getCredentials();

        UserDetails userDetails = null;
        try {
            userDetails = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            // Perform timing attack protection: verify against dummy hash
            // This ensures response time is consistent whether the user exists or password is wrong
            passwordEncoder.matches(credentials != null ? credentials.toString() : "", DUMMY_PASSWORD_HASH);
            throw new BadCredentialsException("Invalid username or password");
        }

        if (userDetails == null) {
            // Perform timing attack protection for null response
            passwordEncoder.matches(credentials != null ? credentials.toString() : "", DUMMY_PASSWORD_HASH);
            throw new BadCredentialsException("Invalid username or password");
        }

        if (credentials == null) {
            throw new BadCredentialsException("Invalid username or password");
        }

        // Verify the credential before returning authenticated token
        if (!passwordEncoder.matches(credentials.toString(), userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
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

The fix adds three critical authentication checks:

1. **PasswordEncoder Injection** - Constructor now accepts a `PasswordEncoder` bean (Spring Security's standard password encoder, typically `BCryptPasswordEncoder`). This enables secure credential verification.

2. **Credential Verification** - Before returning success (line 63), the code now calls `passwordEncoder.matches(credentials.toString(), userDetails.getPassword())`. This compares the plaintext credential from the request against the stored password hash using the encoder's verification logic. If the check fails, `BadCredentialsException` is thrown.

3. **Timing Attack Protection** - User enumeration attacks can determine whether a username exists by measuring response time differences (unknown user fails fast, wrong password hashes BCrypt at full cost). The fix runs `passwordEncoder.matches()` against a dummy BCrypt hash when the user is not found or doesn't exist (lines 44-45 and 50-51). This ensures the response time is indistinguishable from a real password verification failure. The dummy hash (`$2a$10$...`) is a valid 60-character BCrypt hash at cost 10, matching Spring Security's `BCryptPasswordEncoder` default.

The fix also adds a null check for credentials and throws `BadCredentialsException` consistently on all failure paths, preventing authentication bypass through null credentials or missing passwords.

## Behaviour changes

- **Authentication now enforces password verification** - Requests with incorrect passwords are rejected with `BadCredentialsException`, preventing login with any credentials
- **User enumeration protection** - Response time for non-existent users now matches wrong-password responses due to dummy hash verification
- **Null credential rejection** - Requests without a password are rejected instead of succeeding
- **Required dependency** - PasswordEncoder bean must be available in the Spring context for constructor injection to succeed
- **Exception changes** - Invalid credentials now throw `BadCredentialsException` instead of silently succeeding; `UsernameNotFoundException` from the service is caught and converted to a generic `BadCredentialsException` to avoid leaking user existence information
