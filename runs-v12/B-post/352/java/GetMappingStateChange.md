## Verdict

**Confirmed exploitable.** A `@GetMapping` that performs a state-changing operation (account deletion) bypasses Spring Security's CSRF protection, which validates only non-safe HTTP methods. An attacker can craft a link that, when clicked by an authenticated user, deletes the user's account without presenting a CSRF token.

## Source

HTTP GET request to `/account/delete` endpoint, attacker-supplied via malicious link embedded in a web page or email.

## Fix

Split the endpoint into two handlers: keep a GET that returns a confirmation form, and add a POST handler that performs the actual deletion with automatic CSRF token validation.

### Vulnerable Code

```java
// Line 38: State change via GET bypasses CSRF protection
@GetMapping("/account/delete")
public String deleteAccount(Authentication authentication) {
    accountService.deleteAccount(authentication.getName());
    return "account deleted";
}
```

### Fixed Code

```java
@GetMapping("/account/delete")
public String showDeleteConfirmation() {
    // Returns a form whose submit targets the POST endpoint with CSRF token
    return "confirmDeleteAccount";  // Thymeleaf template name
}

@PostMapping("/account/delete")
public String deleteAccount(Authentication authentication) {
    // Spring Security's CsrfFilter validates the token for POST requests
    // before this handler is invoked
    accountService.deleteAccount(authentication.getName());
    return "account deleted";
}
```

### Confirmation Form Template (confirmDeleteAccount.html)

The Thymeleaf template referenced by the GET handler includes a form with the CSRF token:

```html
<form method="post" th:action="@{/account/delete}">
  <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}" />
  <p>Are you sure you want to delete your account? This action cannot be undone.</p>
  <button type="submit">Yes, delete my account</button>
  <a href="/account">Cancel</a>
</form>
```

## Explanation

The vulnerability exists because HTTP GET requests are treated as "safe" operations by CSRF filters and are not subject to token validation, even when the endpoint performs a state change. The fix moves the destructive operation to a POST handler, which Spring Security's CsrfFilter always validates for state-changing methods.

The GET endpoint is retained (but changed to return a confirmation page instead of performing the deletion) to maintain backward compatibility with existing links. Users clicking a "delete account" link from the settings page now land on a confirmation form instead of immediately deleting their account. The form includes the CSRF token automatically by the Thymeleaf template, and submission targets the protected POST endpoint.

Spring Security validates the CSRF token before the POST handler executes, ensuring the request originated from the application itself and not from an attacker-controlled site.

## Behaviour changes

- **Before**: Direct link to `/account/delete` in email, bookmark, or malicious page triggers immediate account deletion without confirmation.
- **After**: Link to `/account/delete` displays a confirmation form. User must submit the form (which includes a CSRF token) to complete deletion.
- **Impact**: Legitimate users now see a confirmation step (improved UX safety); attackers can no longer trigger deletion through a simple link. Existing links continue to work (they render the form instead of failing with a 405 or 403).
