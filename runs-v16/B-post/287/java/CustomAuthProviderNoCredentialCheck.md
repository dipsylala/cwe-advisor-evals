## Verdict

exploitable

## Source

The credential (password) originates from untrusted client input via `authentication.getCredentials()` on line 26.

## Sink

Line 34: The `authenticate()` method returns a successful `UsernamePasswordAuthenticationToken` after only checking if the user exists in the database, without verifying that the supplied password matches the stored password.

## Fix

**Vulnerable code (line 24-35):**

```java
@Override
public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
    Object credentials = authentication.getCredentials();

    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
    if (userDetails == null) {
        throw new UsernameNotFoundException("No user found with username: " + username);
    }

    // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
    return new UsernamePasswordAuthenticationToken(userDetails, credentials, userDetails.getAuthorities());
}
```

**Fixed code:**

```java
@Override
public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
    String password = (String) authentication.getCredentials();

    if (password == null || password.isEmpty()) {
        throw new BadCredentialsException("Missing credentials");
    }

    UserDetails userDetails;
    try {
        userDetails = userDetailsService.loadUserByUsername(username);
    } catch (UsernameNotFoundException e) {
        // Timing attack protection: run password encoding against a dummy hash
        // to prevent attackers from timing the response to determine if a username exists
        passwordEncoder.matches(password, "$2a$10$dXJ3SW6G7P50eS3MqsCgfOd6I3NP.dQbfmKfLdAAGWGSpZMSmHVGe");
        throw e;
    }

    if (userDetails == null) {
        throw new BadCredentialsException("User not found");
    }

    // Verify the provided password against the stored encoded password
    if (!passwordEncoder.matches(password, userDetails.getPassword())) {
        throw new BadCredentialsException("Invalid credentials");
    }

    return new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());
}
```

Constructor injection must also be updated to accept `PasswordEncoder`:

```java
private final UserDetailsService userDetailsService;
private final PasswordEncoder passwordEncoder;

public CustomAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
    this.userDetailsService = userDetailsService;
    this.passwordEncoder = passwordEncoder;
}
```

Add import for `BadCredentialsException`:

```java
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
```

## Explanation

The vulnerability occurs because the `authenticate()` method returns a successful authentication after only verifying that the user exists in the database, without checking that the supplied credentials (password) match what is stored. An attacker can authenticate as any existing user by providing any credential value. The fix adds password verification using Spring Security's `PasswordEncoder.matches()` method, which compares the supplied password against the stored encoded password. A `BadCredentialsException` is thrown if the password does not match. The code also implements timing-attack protection by calling `matches()` against a dummy BCrypt hash when the username is not found, ensuring response time does not leak whether a username exists in the system.

## Behaviour changes

- **Constructor now requires `PasswordEncoder` injection**: The provider previously accepted only `UserDetailsService`; it now also requires a `PasswordEncoder` bean to be available in the Spring context. Calling code that instantiates this provider must supply both dependencies.
- **Credentials are now explicitly cast to `String`**: The original code held credentials as `Object` and passed them unchanged to the token. The fixed code casts to `String` before use, which assumes the authentication object carries the password as a string rather than an object. This matches the Spring Security `UsernamePasswordAuthenticationToken` contract.
- **`UsernameNotFoundException` is now caught and re-thrown**: The original code allowed it to propagate uncaught; the fixed code catches it, runs a dummy password verification for timing attack protection, then re-throws it. The exception behavior is unchanged to the caller, but the method now spends CPU time on password hashing before the exception is raised, preventing attackers from timing the response to determine which usernames exist.
- **New exceptions thrown**: `BadCredentialsException` is thrown on missing/invalid password, whereas the original code silently accepted any credential. Callers who catch all `AuthenticationException` subtypes already handle this; callers catching only `UsernameNotFoundException` may need to handle the new exception type.
- **Password null-check added**: The fixed code explicitly checks that the supplied password is not null or empty and throws `BadCredentialsException` if it is. The original code would have passed a null credential through.

