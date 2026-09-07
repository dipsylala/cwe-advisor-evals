## Verdict

Exploitable. The `CustomAuthenticationProvider.authenticate()` method at line 34 returns a successful authentication without verifying the submitted credential against the stored password hash. Any username with a valid account in the user details service is immediately authenticated regardless of the password provided. Additionally, the code is vulnerable to username enumeration via timing attacks: the response time differs between a nonexistent username (throws at line 30) and an existing username (succeeds at line 34).

## Source

Untrusted authentication credential: `authentication.getCredentials()` from the unauthenticated HTTP request, received at line 26.

## Sink

Line 34: `return new UsernamePasswordAuthenticationToken(userDetails, credentials, userDetails.getAuthorities());`

The `authenticate()` method returns a successful `Authentication` object without ever calling `PasswordEncoder.matches()` to verify the supplied credential against the stored password.

## Fix

**Vulnerable code (lines 24–35):**

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

Inject `PasswordEncoder` as a constructor dependency (add to imports and constructor):

```java
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

private final UserDetailsService userDetailsService;
private final PasswordEncoder passwordEncoder;
// Dummy hash for timing attack mitigation: genuine BCrypt hash at standard strength
private static final String DUMMY_PASSWORD_HASH = "$2a$10$dXj3SW6G7P50eS3xNwYtMeUOPTijhCrjYYI9WsLvlLd.kDQ8h4iRG";

public CustomAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
    this.userDetailsService = userDetailsService;
    this.passwordEncoder = passwordEncoder;
}
```

Replace the authenticate method:

```java
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
        // Mitigate timing attack: run password verification against dummy hash
        passwordEncoder.matches(rawPassword, DUMMY_PASSWORD_HASH);
        throw new BadCredentialsException("Invalid username or password");
    }

    if (userDetails == null) {
        passwordEncoder.matches(rawPassword, DUMMY_PASSWORD_HASH);
        throw new BadCredentialsException("Invalid username or password");
    }

    String encodedPassword = userDetails.getPassword();
    if (encodedPassword == null) {
        // SSO-only account: no password to verify
        passwordEncoder.matches(rawPassword, DUMMY_PASSWORD_HASH);
        throw new BadCredentialsException("Invalid username or password");
    }

    // Verify the credential before returning authenticated session
    if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
        throw new BadCredentialsException("Invalid username or password");
    }

    return new UsernamePasswordAuthenticationToken(userDetails, credentials, userDetails.getAuthorities());
}
```

## Explanation

The fix adds a `PasswordEncoder` dependency and verifies the supplied credential via `PasswordEncoder.matches()` before returning a successful `Authentication`. A `BadCredentialsException` is thrown if the password does not match the stored hash. The fix also mitigates username-enumeration timing attacks by running `PasswordEncoder.matches()` against a dummy BCrypt hash even when the username is not found or the user has no password (SSO-only account), so response time does not leak the existence of usernames. The dummy hash is a genuine 60-character BCrypt hash at the encoder's default strength so that the `matches()` call consumes the full cost of password verification. The generic error message "Invalid username or password" prevents information leakage.

## Behaviour changes

- **Constructor signature changed**: Added `PasswordEncoder passwordEncoder` parameter. Reason: required to verify the password credential.
- **New imports**: `BadCredentialsException`, `PasswordEncoder`. Reason: bad credentials are thrown explicitly; password verification is delegated to the configured encoder.
- **New static field**: `DUMMY_PASSWORD_HASH`. Reason: timing attack mitigation requires a BCrypt hash to verify against when the user is not found, so response time is constant between valid and invalid usernames.
- **New null check on credentials**: Early return with `BadCredentialsException` if credentials are null. Reason: prevents null pointer exceptions and enforces that a password is always provided.
- **New try/catch around `loadUserByUsername()`**: Catches `UsernameNotFoundException` explicitly to run `matches()` before re-throwing. Reason: timing attack mitigation; without this, a non-existent username returns immediately without running the expensive `matches()` operation.
- **New null checks on `userDetails` and `userDetails.getPassword()`**: Both cases run `matches()` against the dummy hash and throw `BadCredentialsException` with a generic message. Reason: ensures constant-time failure paths for nonexistent users and SSO-only accounts.
- **New credential verification**: `passwordEncoder.matches(rawPassword, encodedPassword)` with exception on mismatch. Reason: closes the authentication bypass; any password that does not match the stored hash is rejected.
- **Error messages changed**: From `UsernameNotFoundException` to `BadCredentialsException` with generic message. Reason: prevents username enumeration and follows Spring Security best practice of never confirming the existence of usernames to unauthenticated callers.
