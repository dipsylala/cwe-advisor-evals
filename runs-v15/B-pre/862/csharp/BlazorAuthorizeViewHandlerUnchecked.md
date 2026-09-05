## Verdict

Exploitable

## Source

`UserId` parameter from the route (line 25), used in the call to `AccountService.DeleteAccountAsync(UserId)` at line 37. The route parameter is attacker-controlled and can be any user ID.

## Fix

**Vulnerable code (line 32-40):**

```csharp
private async Task DeleteAccount()
{
    isDeleting = true;

    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    await AccountService.DeleteAccountAsync(UserId);

    NavigationManager.NavigateTo("/admin/accounts");
}
```

**Fixed code:**

```csharp
private async Task DeleteAccount()
{
    // Verify authorization server-side: AuthorizeView only controls rendering,
    // not invocation of this event handler.
    var authState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
    if (!authState.User.IsInRole("Admin"))
    {
        // Authorization denied - do not proceed
        return;
    }

    isDeleting = true;

    await AccountService.DeleteAccountAsync(UserId);

    NavigationManager.NavigateTo("/admin/accounts");
}
```

**Required injection addition (line 3-4):**

Add to the `@inject` directives:

```csharp
@inject AuthenticationStateProvider AuthenticationStateProvider
```

## Explanation

The vulnerability arises because `AuthorizeView` is a rendering control only—it hides the UI button from non-admins but does not prevent the `DeleteAccount()` event handler itself from being invoked. An attacker can trigger the handler through browser developer tools, JavaScript console manipulation, or by intercepting and modifying requests. The fix adds an explicit, server-side authorization check inside the handler before the sensitive operation executes. The handler now retrieves the authentication state and verifies the caller is in the Admin role; only then does it proceed to call `AccountService.DeleteAccountAsync()`. This ensures the authorization decision is enforced at the server, not controlled by the client.

## Behaviour changes

The fixed code adds an authorization check that may return early (line 35) without deleting the account or navigating if the user is not in the Admin role. The original code had no such check and would proceed unconditionally. Additionally, the fixed code calls `await AuthenticationStateProvider.GetAuthenticationStateAsync()` to obtain the authentication state before the operation, which adds an async call and a small latency; this is necessary for correct authorization and is not a regression—it ensures the operation only proceeds when authorized.
