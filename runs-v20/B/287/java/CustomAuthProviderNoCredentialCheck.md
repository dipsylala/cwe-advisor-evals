## Verdict

exploitable

## Source

`authenticate(Authentication authentication)` receives an `Authentication` object populated from the login request - `authentication.getName()` (submitted username) and `authentication.getCredentials()` (submitted password) at lines 25-26 of `CustomAuthenticationProvider.java`.

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

import java.util.UUID;

// Targets Spring Security 6.3. Custom AuthenticationProvider used in place of
// the framework's DaoAuthenticationProvider for a legacy login flow.
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    // Encoded once at construction so a lookup miss still pays the same
    // hashing cost as a real user, instead of returning early and leaking
    // which usernames exist via response timing.
    private final String dummyPasswordHash;

    public CustomAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.dummyPasswordHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        Object credentials = authentication.getCredentials();
        String rawPassword = (credentials != null) ? credentials.toString() : null;

        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException ex) {
            if (rawPassword != null) {
                passwordEncoder.matches(rawPassword, dummyPasswordHash);
            }
            throw new BadCredentialsException("Bad credentials");
        }

        if (userDetails == null) {
            if (rawPassword != null) {
                passwordEncoder.matches(rawPassword, dummyPasswordHash);
            }
            throw new BadCredentialsException("Bad credentials");
        }

        if (rawPassword == null || userDetails.getPassword() == null
                || !passwordEncoder.matches(rawPassword, userDetails.getPassword())) {
            throw new BadCredentialsException("Bad credentials");
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

The original `authenticate()` looked up the user and, provided a `UserDetails` record existed, unconditionally wrapped the submitted credentials into an authenticated `UsernamePasswordAuthenticationToken` - the submitted password was read into `credentials` but never compared against `userDetails.getPassword()`, so any password (or none) authenticated any known username. The fix injects the application's `PasswordEncoder` and requires `passwordEncoder.matches(rawPassword, userDetails.getPassword())` to succeed before a token is returned; any failure - wrong password, unknown user, missing credential, or a user record with no password hash (e.g. an SSO-only account) - now throws `BadCredentialsException` instead of falling through to success. The unknown-username branch also runs `passwordEncoder.matches()` against a dummy hash generated once at construction, so a lookup miss costs the same as a real comparison and can't be timed to enumerate usernames.

## Behaviour changes

- Constructor signature changed from `CustomAuthenticationProvider(UserDetailsService)` to `CustomAuthenticationProvider(UserDetailsService, PasswordEncoder)`. Required to perform the credential check at all; assumes a `PasswordEncoder` bean is already defined in the application's Spring configuration (the conventional setup alongside a custom `AuthenticationProvider`) so autowiring succeeds. If no such bean exists, this is a new dependency the application must supply.
- A submission with a known username but wrong/missing password, or a user record with a null password, now throws `BadCredentialsException` instead of authenticating. This is the fix itself, not incidental scope creep - it is the exact behaviour the finding reports as missing.
- Unknown-username lookups now perform a `passwordEncoder.matches()` call against a fixed-cost dummy hash before throwing, adding a bounded, constant amount of CPU work to every failed login on an unknown username. This closes a response-timing user-enumeration side channel documented for this exact provider pattern in the loaded guidance; it does not change the returned exception type or message (`BadCredentialsException`, "Bad credentials" - the original already threw `UsernameNotFoundException`, which callers see identically as an `AuthenticationException`).
- Successful authentication still returns `credentials` unmodified in the token (same as the original), so no change to what a caller sees post-authentication; Spring's default `ProviderManager` erases credentials from the result afterward regardless.

## Verification

Compiled with `javac` against `spring-security-core-6.3.4.jar`, `spring-security-crypto-6.3.4.jar`, `spring-context-6.1.12.jar`, `spring-core-6.1.12.jar`, and `spring-beans-6.1.12.jar` (resolved from the local Maven repository, matching the file's stated Spring Security 6.3 target). Compilation succeeded with no errors or warnings. Every newly introduced symbol - `BadCredentialsException`, `PasswordEncoder` (`org.springframework.security.crypto.password`), `UUID` (`java.util`) - is either named in the loaded CWE-287 Java guidance (`BadCredentialsException`, `PasswordEncoder.matches()`) or from the JDK standard library (`java.util.UUID`); none are unverified.

## Assumptions

- Assumed a `PasswordEncoder` bean is already configured elsewhere in the application (standard for a Spring Security app using a custom `AuthenticationProvider`); this fix does not define one, since the encoder algorithm/strength is an application-level decision the finding's file does not disclose. Confidence: high given the standard Spring Security convention, though unverified against the rest of the application's configuration.
- `userDetails.getPassword()` is assumed to hold a hash in the format the injected `PasswordEncoder` produces (e.g. BCrypt if `BCryptPasswordEncoder` is configured) - consistent with a normal `UserDetailsService` implementation.
