## Verdict

**Confirmed - Improper Authentication (CWE-287)**

The custom `AuthenticationProvider.authenticate()` method returns a successful authentication token without validating that the supplied password matches the stored password hash. An attacker can log in as any user by entering any password, provided the username exists in the system.

## Source

**File**: `CustomAuthenticationProvider.java`  
**Line**: 34 (return statement)  
**Code**: `new UsernamePasswordAuthenticationToken(userDetails, credentials, userDetails.getAuthorities())`

The vulnerability exists in the `authenticate()` method flow:
1. Line 25-26: Extract username and credentials from the request
2. Line 28: Load user details from the database
3. Line 29-31: Verify the user exists
4. Line 34: **Return successful authentication without checking if the password is correct**

The credentials are never validated against the user's stored password hash.

## Fix

Add a `PasswordEncoder` dependency to the class and validate the credentials before returning success. Throw `BadCredentialsException` if the password does not match. Implement timing-attack protection by running the password check even when the user is not found.

**Fixed code**:

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
        String rawPassword = (credentials != null) ? credentials.toString() : "";

        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            // Timing attack protection: run password check even when user not found
            // Use a dummy hash to avoid leaking whether the username exists
            passwordEncoder.matches(rawPassword, "$2a$10$dXJ3SW6G7P50eS7DlH0/vu8l/XgC2KJ2MBnBvXmGb4D6KhvBiKxdS");
            throw e;
        }

        if (userDetails == null) {
            throw new UsernameNotFoundException("No user found with username: " + username);
        }

        // Validate the supplied password against the stored hash
        if (!passwordEncoder.matches(rawPassword, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid password for user: " + username);
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

The fix adds three key changes:

1. **Injected PasswordEncoder**: A `PasswordEncoder` bean (typically `BCryptPasswordEncoder`) is injected via constructor to securely verify passwords.

2. **Password validation**: Before returning success (line 42), the code now calls `passwordEncoder.matches(rawPassword, userDetails.getPassword())` to verify the supplied password against the stored hash. If the passwords do not match, `BadCredentialsException` is thrown immediately, denying the login.

3. **Timing-attack protection**: When `loadUserByUsername()` throws `UsernameNotFoundException`, the code still runs `passwordEncoder.matches()` against a dummy BCrypt hash (line 38) before re-throwing the exception. This ensures that the time taken to reject an unknown username is indistinguishable from the time taken to reject a wrong password, preventing attackers from using response time to enumerate valid usernames.

The fix ensures the authentication logic follows Spring Security best practices: never return success without credential verification, and always run expensive cryptographic checks to mask account existence.

## Behaviour changes

- **Login with wrong password**: Previously succeeded; now throws `BadCredentialsException` and returns 401. **Breaking change** - existing clients relying on the bypass will need to supply correct credentials.
- **Login for non-existent user**: Response time is now constant, matching the time for a real user with wrong password. Previously, the response was faster. **Security hardening** - no breaking change to API contract.
- **Successful login**: Unchanged - users with correct credentials receive an authenticated `Authentication` token.
- **Dependency requirement**: The class now requires a `PasswordEncoder` bean in the Spring context. If not already configured, clients must provide one (e.g., `@Bean BCryptPasswordEncoder`). **New requirement**.
