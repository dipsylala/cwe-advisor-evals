## Verdict

Confirmed. `UserAccountService.deleteUserAccount` and `suspendUserAccount` are annotated with `@PreAuthorize("hasRole('ADMIN')")`, but nothing in the application enables Spring Security's method-security interceptor. Without an `@EnableMethodSecurity` (or the older `@EnableGlobalMethodSecurity`) configuration, Spring Security never registers the `AuthorizationManagerBeforeMethodInterceptor` that evaluates `@PreAuthorize`, so the annotation is inert metadata: any caller with a `UserAccountRepository` reference reaches `deleteById(userId)` with no role check performed. This is CWE-862 (Missing Authorization) - the intended authorization check exists in source but is never wired into the runtime enforcement path.

## Source

`userId`, a `long` passed into `deleteUserAccount(long userId)` (`UserAccountService.java:16`), flowing directly and unvalidated-by-authorization into `userAccountRepository.deleteById(userId)` at line 18. There is no caller-identity or role check actually enforced before the delete executes, because the `@PreAuthorize` guard on line 15 has no effect without global method security enabled.

## Fix

### File: MethodSecurityConfig.java

```java
package com.example.accounts;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {
    // Enables Spring Security's method-security interceptor so that
    // @PreAuthorize / @PostAuthorize / @Secured annotations on service
    // beans (e.g. UserAccountService) are actually enforced at runtime.
}
```

## Explanation

`@PreAuthorize` is only a marker annotation processed by an AOP interceptor that Spring Security registers when method security is turned on. In modern Spring Security (5.6+), that is done with `@EnableMethodSecurity` on a `@Configuration` class, which by default activates pre/post-authorization checks (the equivalent of `prePostEnabled = true` under the legacy `@EnableGlobalMethodSecurity`, which is deprecated in favor of `@EnableMethodSecurity` and should not be used in new code). Without this annotation present anywhere in the application context, Spring Security never proxies `UserAccountService`, so `hasRole('ADMIN')` is never evaluated and `deleteUserAccount`/`suspendUserAccount` are callable by anyone who can invoke the bean - including unauthenticated pathways in the surrounding call chain.

The fix adds a small `@Configuration` class carrying `@EnableMethodSecurity`. This is additive and non-breaking: it does not change `UserAccountService` itself, and it activates enforcement for every `@PreAuthorize`/`@PostAuthorize`/`@Secured` annotation already declared in the codebase, not just the two methods shown here. No existing behavior for correctly-authorized callers changes; only unauthorized calls, which should have been rejected all along, now are.

To verify: with the interceptor enabled, a request or test invoking `deleteUserAccount`/`suspendUserAccount` under a principal lacking `ROLE_ADMIN` must now fail with an `AccessDeniedException` (HTTP 403 at the web layer), whereas before this fix the same call reached `deleteById`/`save` unconditionally. Confirm this with a Spring Security test context (`@WithMockUser(roles = "USER")` calling the service and asserting `AccessDeniedException`, plus a second `@WithMockUser(roles = "ADMIN")` case asserting success) - a test that only checks the annotation is present, without an enabled method-security context backing it, would pass identically before and after this fix and would prove nothing.
