## Verdict

This is a valid CWE-862 (Missing Authorization) finding. The `deleteUserAccount` method intends to restrict access to administrators via the `@PreAuthorize("hasRole('ADMIN')")` annotation, but the authorization check is never enforced because Spring Security's method-level security is not globally enabled. As a result, any authenticated user can delete accounts.

## Source

**File:** UserAccountService.java, line 18

```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteUserAccount(long userId) {
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    userAccountRepository.deleteById(userId);
}
```

The `@PreAuthorize` annotation on line 15 is declarative but has no effect without global method security enabled.

## Fix

### File: SecurityConfig.java

```java
package com.example.accounts;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
```

## Explanation

The vulnerability exists because Spring Security does not automatically enforce method-level authorization annotations like `@PreAuthorize` and `@PostAuthorize`. These annotations are only evaluated when method security is explicitly enabled via the `@EnableMethodSecurity` annotation on a configuration class.

The fix adds `@EnableMethodSecurity` to the `SecurityConfig` class (line 10) and imports the required annotation (line 6). This activates Spring Security's method interceptor, which now evaluates the `@PreAuthorize("hasRole('ADMIN')")` annotation before executing `deleteUserAccount()`. Unauthenticated users and users without the `ADMIN` role will receive an `AccessDeniedException`.

The `@EnableMethodSecurity` annotation is the modern Spring Security 6.0+ approach; it replaces the deprecated `@EnableGlobalMethodSecurity` and enables support for `@PreAuthorize`, `@PostAuthorize`, `@PreFilter`, and `@PostFilter` annotations on methods.
