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
        // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
        return Authentication.class.isAssignableFrom(authentication);
    }
}
