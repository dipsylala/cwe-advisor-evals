## Verdict
exploitable

## Source
Line 42: `supports(Class<?> authentication)` method returns `true` for any `Authentication` subclass via `Authentication.class.isAssignableFrom(authentication)`

## Sink
The return value of `supports()` is used by Spring Security's `ProviderManager` to determine whether this `AuthenticationProvider` can handle a given authentication type. When `supports()` returns `true`, `ProviderManager` delegates the authentication request to this provider's `authenticate()` method, which expects an `ApiKeyAuthenticationToken` specifically (line 27).

## Fix

### File: ApiKeyAuthenticationProvider.java

```java
package com.example.security.apikey;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

// Targets Spring Security 6.3. Registered alongside DaoAuthenticationProvider in the
// ProviderManager so that requests carrying an ApiKeyAuthenticationToken (built by
// ApiKeyAuthenticationFilter from the X-Api-Key header) are verified against the
// api_keys table instead of the username/password store.
@Component
public class ApiKeyAuthenticationProvider implements AuthenticationProvider {

    private final ApiKeyRepository apiKeyRepository;
    private final PasswordEncoder passwordEncoder;

    public ApiKeyAuthenticationProvider(ApiKeyRepository apiKeyRepository, PasswordEncoder passwordEncoder) {
        this.apiKeyRepository = apiKeyRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        ApiKeyAuthenticationToken token = (ApiKeyAuthenticationToken) authentication;
        String clientId = String.valueOf(token.getPrincipal());
        String presentedKey = String.valueOf(token.getCredentials());

        ApiKeyRecord record = apiKeyRepository.findByClientId(clientId);
        if (record == null || !passwordEncoder.matches(presentedKey, record.getHashedKey())) {
            throw new BadCredentialsException("Invalid API key for client " + clientId);
        }

        return new ApiKeyAuthenticationToken(record.getClientId(), null, record.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ApiKeyAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
```

## Explanation
The provider's `supports()` method was returning `true` for any `Authentication` subclass, allowing Spring Security's `ProviderManager` to incorrectly delegate unintended authentication types to this provider. The `authenticate()` method expects and casts to `ApiKeyAuthenticationToken` specifically (line 27), so the `supports()` method must return `true` only for that exact type and its subclasses. The fix changes the class check from the base `Authentication` class to `ApiKeyAuthenticationToken`, ensuring `ProviderManager` only delegates API key authentication attempts to this provider, preventing authentication bypass and keeping authentication type routing consistent with the provider's actual capabilities.

## Behaviour changes
The `supports()` method now returns `true` only when passed `ApiKeyAuthenticationToken.class` or a subclass thereof, instead of returning `true` for any `Authentication` subclass. This aligns the `supports()` contract with what `authenticate()` actually handles. No other code paths are affected. The sink contract remains intact: `supports()` still returns a boolean that `ProviderManager` uses for delegation, and no new exceptions or return values are introduced.

