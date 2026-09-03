## Verdict

Exploitable. The event handler performs a sensitive operation (account deletion) without verifying the caller's authorization, relying solely on UI-level rendering checks that do not enforce server-side access control.

## Source

Route parameter `UserId` supplied via the page directive `@page "/admin/accounts/{UserId}"`, derived from the URL path. No external validation confirms the caller is authorized to delete the specified account.

## Fix

**Vulnerable Code (lines 32-40):**
```csharp
private async Task DeleteAccount()
{
    isDeleting = true;

    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    await AccountService.DeleteAccountAsync(UserId);

    NavigationManager.NavigateTo("/admin/accounts");
}
```

**Fixed Code:**
```csharp
@inject AuthenticationStateProvider AuthenticationStateProvider

private async Task DeleteAccount()
{
    var authState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
    if (!authState.User.IsInRole("Admin"))
    {
        throw new UnauthorizedAccessException("Only administrators can delete accounts.");
    }

    isDeleting = true;

    await AccountService.DeleteAccountAsync(UserId);

    NavigationManager.NavigateTo("/admin/accounts");
}
```

Add the `AuthenticationStateProvider` injection at the top of the component (after the existing `@inject` statements).

## Explanation

The component uses `<AuthorizeView Roles="Admin">` to conditionally render the delete button only to administrators. However, `AuthorizeView` controls what markup renders to the client, not what executes on the server. The `DeleteAccount()` event handler is a regular method that runs server-side for any caller who reaches it, regardless of role.

The fix adds an explicit role check inside the event handler using `AuthenticationStateProvider.GetAuthenticationStateAsync()` to retrieve the authenticated user's claims and verify membership in the "Admin" role. If the check fails, the method throws `UnauthorizedAccessException` before invoking the service, enforcing authorization server-side and preventing role bypass through direct component method invocation or interception.

## Behaviour changes

- **Added dependency injection**: `AuthenticationStateProvider` is now injected into the component. This is a standard ASP.NET Core service and introduces no new vulnerabilities.
- **Synchronous-to-asynchronous conversion**: The authorization check calls `GetAuthenticationStateAsync()`, making `DeleteAccount()` remain async (it already was). No change to the method signature.
- **Exception on unauthorized access**: The method now throws `UnauthorizedAccessException` instead of silently proceeding when the user lacks the Admin role. This is a behavior change that prevents the sensitive operation and surfaces the authorization failure to the Blazor error handling infrastructure. The caller receives an error instead of success—the correct security behavior.
- **No change to success path**: When the user is authorized, the method proceeds identically to the original.
