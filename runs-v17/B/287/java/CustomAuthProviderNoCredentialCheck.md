## Verdict

Exploitable. The `authenticate()` method accepts any credentials without verifying them against the stored password, completing an authentication bypass that grants attackers access to any account without knowledge of the password.

## Source

Line 26: `Object credentials = authentication.getCredentials();` - the raw password credential from the HTTP request, and line 28: `UserDetails userDetails = userDetailsService.loadUserByUsername(username);` - the user record fetched from the service.

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

        if (credentials == null) {
            throw new BadCredentialsException("No credentials provided");
        }

        String rawPassword = credentials.toString();
        UserDetails userDetails;

        try {
            userDetails = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            // Prevent timing attacks by running the encoder against a dummy password
            // even when the user is not found, so response time does not leak user existence
            passwordEncoder.matches(rawPassword, "$2a$10$dXJ3SW6G7P50eS3BQObvOu1.0+3/bNxzSzUl7YB3BuNmOQh5Jcjqy");
            throw new BadCredentialsException("Invalid username or password");
        }

        if (userDetails == null || userDetails.getPassword() == null) {
            throw new BadCredentialsException("Invalid username or password");
        }

        // Verify the password before accepting authentication
        if (!passwordEncoder.matches(rawPassword, userDetails.getPassword())) {
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

The original code loads user details from the database but returns a successful `UsernamePasswordAuthenticationToken` without verifying the supplied credentials against the stored password. The fix adds three critical verifications: (1) checking that credentials are present, (2) verifying the raw password against the encoded stored password using `PasswordEncoder.matches()`, and (3) throwing `BadCredentialsException` on any mismatch. Additionally, the fix prevents timing attacks by calling the encoder against a dummy BCrypt hash when the user is not found, ensuring response time does not leak whether a username exists in the system. Spring Security's built-in `PasswordEncoder` bean is injected and used for all password comparisons, maintaining consistency with the framework's cryptographic standards.

## Behaviour changes

- **Constructor parameter added**: `PasswordEncoder passwordEncoder` parameter injected to support password verification.
- **Null check for credentials**: Added validation that credentials are not null before attempting to use them; throws `BadCredentialsException` if null.
- **String conversion of credentials**: `credentials.toString()` converts the credential object to string for password comparison.
- **Null check for userDetails and password**: Explicitly validates that the loaded user details and its password are not null before verification; this handles SSO-only accounts where password is null.
- **Password verification**: Added `passwordEncoder.matches(rawPassword, userDetails.getPassword())` call to cryptographically verify the supplied password against the stored encoded password; authentication succeeds only if this returns true.
- **Timing attack mitigation**: On `UsernameNotFoundException`, the encoder is called against a dummy BCrypt hash before re-throwing the exception, consuming the same time as a legitimate password check and preventing user-enumeration attacks based on response time.
- **Exception type changed**: All failures now throw `BadCredentialsException` with a generic message ("Invalid username or password") instead of `UsernameNotFoundException`, which masks user existence and prevents leaking account enumeration information.
- **Exception import added**: Added `org.springframework.security.authentication.BadCredentialsException` import.
- **PasswordEncoder import added**: Added `org.springframework.security.crypto.password.PasswordEncoder` import.
- **Field added**: New private final field `passwordEncoder` to hold the injected encoder instance.
- **Return statement unchanged**: The `return new UsernamePasswordAuthenticationToken(...)` statement structure is identical; only the preceding guards change to ensure the method never reaches this line with an invalid password.

No behaviour changes are introduced to the `supports()` method or to successful authentication flow beyond the credential verification gate. A valid username and password continue to produce an authenticated `UsernamePasswordAuthenticationToken` with the user's granted authorities.
