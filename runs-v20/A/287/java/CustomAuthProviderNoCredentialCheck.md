## Verdict

Confirmed. `authenticate()` loads the user by username and then unconditionally builds an authenticated `UsernamePasswordAuthenticationToken` from the supplied credentials, without ever comparing the presented password to the stored one. Any caller who knows (or guesses) a valid username is authenticated regardless of what password they supply, including an empty or arbitrary value.

## Source

The presented credentials originate from `authentication.getCredentials()` at line 26, which for a login flow carries the raw password submitted by the client via the `UsernamePasswordAuthenticationToken` built upstream (e.g. by the login controller/filter). This value is never validated before being trusted.

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

        if (credentials == null || !passwordEncoder.matches(credentials.toString(), userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }

        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```

## Explanation

The original code treated `loadUserByUsername` succeeding as proof of authentication and skipped the actual credential check, which is the essence of CWE-287. The fix adds a `PasswordEncoder` dependency (the standard Spring Security abstraction, normally backed by `BCryptPasswordEncoder`) and uses `passwordEncoder.matches(rawPassword, encodedPassword)` to compare the submitted credential against the stored, hashed password on `userDetails.getPassword()`. `matches` is used rather than re-hashing and comparing strings directly, since password hashes are salted and non-deterministic. A `null` credential is rejected outright rather than passed to `matches`, since some `PasswordEncoder` implementations do not tolerate a null raw password. On mismatch, a `BadCredentialsException` is thrown, matching the exception type Spring Security's standard providers use for this case so downstream failure handlers behave consistently. Once authentication succeeds, the returned token no longer carries the raw credential (it is set to `null`), following the same convention as `DaoAuthenticationProvider`, since the password is no longer needed after verification and should not be retained in the security context.
