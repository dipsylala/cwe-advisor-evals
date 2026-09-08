## Verdict
Real vulnerability. Line 34 authenticates the user without verifying credentials, allowing authentication to succeed for any password.

## Source
The CustomAuthenticationProvider loads a UserDetails object but returns a successful authentication token without checking if the provided credentials (password) match the stored password. Only user existence is verified; credential validation is missing.

## Fix
### File: CustomAuthenticationProvider.java
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

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (userDetails == null) {
            throw new UsernameNotFoundException("No user found with username: " + username);
        }

        // Validate credentials against stored password
        String rawPassword = credentials != null ? credentials.toString() : "";
        if (!passwordEncoder.matches(rawPassword, userDetails.getPassword())) {
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
The vulnerability exists because the authenticate method accepts any credentials for a valid username. The fix adds credential validation by:

1. Injecting a PasswordEncoder via constructor, enabling cryptographic password verification.
2. Extracting the raw password from the Authentication object's credentials.
3. Using `passwordEncoder.matches()` to compare the provided password against the stored encoded password in UserDetails.
4. Throwing `BadCredentialsException` if the comparison fails, preventing authentication with incorrect passwords.
5. Only returning an authenticated token if the credentials are verified.

This ensures authentication only succeeds when both the username exists and the password is correct, eliminating the CWE-287 vulnerability.
