## Verdict

Exploitable

## Source

Username and password from `UsernamePasswordAuthenticationToken` via `authentication.getName()` and `authentication.getCredentials()` at lines 25-26.

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
    // A genuine 60-character BCrypt hash used for timing attack protection when user not found
    private final String userNotFoundPassword = "$2a$10$slYQmyNdGzin7olVN3p5be4DlH.PKZbv5H8KnzzVgXXbVxzy4Daye";

    public CustomAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        Object credentials = authentication.getCredentials();
        
        if (credentials == null) {
            throw new BadCredentialsException("No password provided");
        }
        
        String rawPassword = credentials.toString();
        
        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            // Run timing attack protection: verify against dummy hash before throwing
            passwordEncoder.matches(rawPassword, userNotFoundPassword);
            throw new BadCredentialsException("Invalid username or password");
        }
        
        if (userDetails == null) {
            // Run timing attack protection: verify against dummy hash before throwing
            passwordEncoder.matches(rawPassword, userNotFoundPassword);
            throw new BadCredentialsException("Invalid username or password");
        }
        
        // Verify the credential against the stored password
        String storedPassword = userDetails.getPassword();
        if (storedPassword == null || !passwordEncoder.matches(rawPassword, storedPassword)) {
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

The original `authenticate()` method returned a successful `UsernamePasswordAuthenticationToken` whenever a user with the given username existed, without verifying that the supplied password matched the stored credential. An attacker could authenticate as any known user by providing any password or none at all.

The fix adds three layers of authentication hardening: (1) `PasswordEncoder` is injected and used to verify the supplied password against the stored hash via `matches()`, and authentication succeeds only if they match; (2) when a `UsernameNotFoundException` is raised or when `loadUserByUsername()` returns `null`, the code still runs `matches()` against a dummy BCrypt hash before throwing `BadCredentialsException`, so an attacker cannot use response time to enumerate which usernames exist; and (3) credential null checks and generic error messages prevent leaking whether a failure is due to missing credentials or invalid credentials. The fix implements the Spring Security 6.3 guidance pattern of moving away from custom providers toward `UserDetailsService` + `PasswordEncoder` beans, but hardens a retained custom provider against the most common bypass.

## Behaviour changes

- Constructor signature changed to require `PasswordEncoder` injection: `PasswordEncoder passwordEncoder` parameter added. Reason: required to call `passwordEncoder.matches()` for credential verification.
- New instance variable `userNotFoundPassword` added: a 60-character BCrypt hash used for timing attack protection. Reason: per guidance, when user not found, code must run `matches()` against a dummy hash to prevent username enumeration via response time.
- Added credential null check at line 36, throwing `BadCredentialsException` on `null`. Reason: prevent NPE and fail closed on missing credentials.
- Changed `loadUserByUsername()` call to wrap in try-catch for `UsernameNotFoundException`. Reason: per guidance, catch the exception and run timing-attack protection before re-throwing.
- Added null check at line 50 and timing-attack protection at line 52. Reason: `UserDetailsService` contract permits returning `null`, which must be treated as user-not-found for timing uniformity.
- Added password verification at lines 55-57: extract `userDetails.getPassword()` and call `passwordEncoder.matches(rawPassword, storedPassword)`, throwing `BadCredentialsException` if the check fails or password is null. Reason: this is the core fix - authenticate only after verifying the credential.
- Error messages changed from username-specific exceptions to generic "Invalid username or password" and "No password provided". Reason: prevent username enumeration in error messages and log output.
- Return statement at line 59 unchanged: still returns successful `UsernamePasswordAuthenticationToken` with authorities, but now only after credentials have been verified.

