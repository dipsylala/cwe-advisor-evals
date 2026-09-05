## Verdict
Exploitable

## Source
UserId parameter from the route `@page "/admin/accounts/{UserId}"` (line 1), passed as an attacker-controlled account identifier.

## Fix

**Vulnerable code:**
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
[CascadingParameter]
private Task<AuthenticationState>? AuthenticationStateTask { get; set; }

private async Task DeleteAccount()
{
    if (AuthenticationStateTask == null)
    {
        return;
    }

    var authState = await AuthenticationStateTask;
    var user = authState.User;

    // Verify the user is in the Admin role before proceeding
    if (!user.IsInRole("Admin"))
    {
        NavigationManager.NavigateTo("/error/unauthorized");
        return;
    }

    isDeleting = true;

    await AccountService.DeleteAccountAsync(UserId);

    NavigationManager.NavigateTo("/admin/accounts");
}
```

Add the required import at the top of the file if not already present:
```csharp
@using Microsoft.AspNetCore.Components.Authorization
```

## Explanation
The vulnerability occurs because `AuthorizeView` only controls rendering of UI elements—it does not prevent the event handler from being invoked directly. An attacker who can trigger the `DeleteAccount()` method (through client-side script modification in WebAssembly scenarios, or by intercepting the event) can delete any account without authorization. The fix adds an explicit server-side authorization check by retrieving the authentication state via a `CascadingParameter`, extracting the current user's claims principal, and verifying the user holds the "Admin" role before executing the sensitive operation. This enforcement ensures the authorization decision runs server-side and cannot be bypassed by client manipulation.

## Behaviour changes
Added a `CascadingParameter` property to receive the `AuthenticationState`. The method now awaits the authentication state task and checks the user's role before proceeding; it navigates to an unauthorized page and returns early if the role check fails. This adds a network call to retrieve auth state (asynchronous operation already in flight) and introduces an early-exit branch when authorization is insufficient. The method's return type and invocation remain unchanged. The sensitive operation (`AccountService.DeleteAccountAsync`) is now guarded by a server-enforced role check and will not execute without proper authorization.
