## Verdict
exploitable

## Source
Attacker-crafted HTTP requests to state-changing API endpoints under `/api/**` (other than webhooks).

## Fix
Change line 24 from:
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
```

to:
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/webhooks/**"))
```

## Explanation
The vulnerability is an over-broad exclusion pattern. The intent is to exclude only `/api/webhooks/**` from CSRF protection because third-party payment providers POST callbacks there without CSRF tokens. However, the current pattern `/api/**` excludes the entire `/api/` tree, including authenticated state-changing endpoints like `/api/account/**` or `/api/orders/**` that must retain CSRF protection. This allows attackers to forge requests to those endpoints and execute state changes on behalf of authenticated users. The fix narrows the exclusion to only the webhook endpoint where third-party callbacks are expected, restoring CSRF protection to all other `/api/` routes.

## Behaviour changes
None. The fix changes only the scope of the CSRF exclusion. All previously protected routes remain protected; the webhook endpoint continues to be unprotected as required. No arguments, return values, or call semantics change.
