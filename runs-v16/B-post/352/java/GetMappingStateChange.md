## Verdict

CONFIRMED. The `@GetMapping("/account/delete")` endpoint at line 38 performs a state-changing operation without CSRF protection. GET methods are treated as "safe" by Spring Security's CSRF filter and bypass token validation entirely. An attacker can exploit this by crafting a link or embedding an image tag that forces an authenticated victim's browser to delete their account.

## Source

Attacker-controlled website or email containing a link to `/account/delete`, executed in the victim's authenticated browser session.

## Fix

The endpoint currently serves as a convenience route that expects a plain link, so changing only the HTTP method would break existing links. The proper fix provides two endpoints:

1. **Keep GET for confirmation** (returns HTML form, not state-changing):
```java
@Controller  // NOT @RestController
public class AccountDeletionController {

    private final AccountService accountService;

    public AccountDeletionController(AccountService accountService) {
        this.accountService = accountService;
    }

    // Serves a confirmation page with a form that POSTs to the deletion endpoint
    @GetMapping("/account/delete")
    public String showDeleteConfirmation() {
        return "delete-confirmation";  // Returns view name, not response body
    }
}
```

2. **Create POST for actual deletion** (protected by CSRF):
In `AccountController.java`, add:
```java
@PostMapping("/account/delete")
public String deleteAccount(Authentication authentication) {
    accountService.deleteAccount(authentication.getName());
    return "account deleted";
}
```

3. **Confirmation view template** (`delete-confirmation.html`):
```html
<!DOCTYPE html>
<html>
<head><title>Delete Account</title></head>
<body>
    <h1>Confirm Account Deletion</h1>
    <p>This action cannot be undone. Are you sure?</p>
    <form method="POST" action="/account/delete">
        <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
        <button type="submit">Delete My Account</button>
        <a href="/">Cancel</a>
    </form>
</body>
</html>
```

## Explanation

The vulnerability exists because GET methods are exempt from CSRF token validation in Spring Security. The endpoint performs a state change (account deletion) when it should be read-only.

The fix separates concerns:
- **GET `/account/delete`**: Now read-only; returns an HTML confirmation page from a `@Controller` (view-capable) instead of a `@RestController` (API-only). This preserves the ability to reach the endpoint via a plain link while eliminating the state change from the GET handler.
- **POST `/account/delete`**: Performs the actual deletion. Spring Security's CSRF filter automatically validates the token from the form's hidden field before the handler executes. The token is bound to the session and re-issued at login, preventing pre-authentication token replay.

The form's hidden `_csrf` field is populated by Spring's template engine; Spring Security checks it in constant-time comparison before allowing the POST to proceed. The GET endpoint now contains only view logic, breaking the attack chain: an attacker's link to `/account/delete` triggers the confirmation page, not deletion.

## Behaviour changes

- **GET `/account/delete`**: Previously deleted the account immediately; now returns an HTML confirmation page (HTTP 200 with content-type text/html). Existing links to this endpoint will display the confirmation form instead of deleting silently.
- **POST `/account/delete`**: New endpoint. Deletes the account only after the user submits the confirmation form, which includes the CSRF token. Requests without a valid token receive HTTP 403 Forbidden.
- **Required change**: The existing `@RestController` cannot serve the confirmation view (it treats all responses as `@ResponseBody`), so the GET logic must move to a separate `@Controller`. The POST deletion can remain in the existing `RestController`, or both can move to a unified `@Controller` that handles both routes.
