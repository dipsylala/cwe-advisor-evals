## Verdict

Exploitable.

## Source

The `authentication` parameter passed to `supports(Class<?> authentication)` can be any `Authentication` subclass, determined at runtime by Spring Security's `ProviderManager` based on the incoming request.

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

The `supports()` method determines which `AuthenticationProvider` in Spring Security's `ProviderManager` should handle each incoming authentication request. The original implementation checked `Authentication.class.isAssignableFrom(authentication)`, which returns `true` for any subclass of `Authentication`, allowing the provider to be selected for all authentication types—not just API key authentication. This violates Spring Security's contract that a provider should only return `true` for the specific authentication types it is designed to handle.

The fix narrows the check to `ApiKeyAuthenticationToken.class.isAssignableFrom(authentication)`, ensuring this provider only accepts and processes API key tokens. Other authentication types (username/password, OAuth, etc.) are correctly routed to their appropriate providers, preventing misconfiguration from bypassing authentication checks or routing credentials to the wrong validation logic.

## Behaviour changes

None. The change is purely restrictive: it makes the scope check more specific to match the provider's intended contract without altering the `authenticate()` method's logic or return value. The `ProviderManager` will simply route non-API-key authentication attempts to the `DaoAuthenticationProvider` (or another appropriate provider) instead of to this one.
