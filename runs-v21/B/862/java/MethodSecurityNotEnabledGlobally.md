## Verdict

The `deleteUserAccount()` method in `UserAccountService` is annotated with `@PreAuthorize("hasRole('ADMIN')")`, but the Spring application does not enable method-level security globally. Without `@EnableMethodSecurity`, the authorization annotation is inert, and any authenticated user can invoke the method and delete user accounts regardless of role.

## Source

Any authenticated HTTP request to the `deleteUserAccount(long userId)` method in the Spring application.

## Sink

The `userAccountRepository.deleteById(userId)` call at line 18 in `UserAccountService.deleteUserAccount()` executes without authorization enforcement.

## Fix

### File: SecurityConfig.java

```java
package com.example.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
}
```

## Explanation

The `@PreAuthorize` annotations in `UserAccountService` declare authorization intent but are not enforced because the Spring application lacks a configuration class annotated with `@EnableMethodSecurity`. Spring Boot's security starter does not activate method-level security by default. Adding a configuration class with `@EnableMethodSecurity` instructs Spring to intercept all method calls and enforce `@PreAuthorize` rules before execution. After this fix, the `deleteUserAccount()` method will raise `AccessDeniedException` for any caller lacking `ROLE_ADMIN`, which Spring's `ExceptionTranslationFilter` translates to HTTP 403 Forbidden for authenticated users.

## Behaviour changes

- **Before**: Any authenticated user could call `deleteUserAccount()` and `suspendUserAccount()`, regardless of role
- **After**: Only users with `ROLE_ADMIN` authority can call these methods; others receive 403 Forbidden

