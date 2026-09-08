## Verdict

The reported CWE-862 (Missing Authorization) vulnerability is confirmed. The `DeleteAccount()` event handler at line 37 calls `AccountService.DeleteAccountAsync(UserId)` without any server-side authorization check. Although the delete button is visually hidden by `<AuthorizeView Roles="Admin">`, the Razor component's event handler can be invoked directly by an attacker, bypassing this UI-level control.

## Source

The vulnerability exists in the `DeleteAccount()` method (lines 32-40). The method receives the `UserId` parameter from the route (line 25) and passes it directly to a sensitive service operation without verifying the caller's authorization:

```csharp
private async Task DeleteAccount()
{
    isDeleting = true;
    // SAST FINDING: No authorization check before this call
    await AccountService.DeleteAccountAsync(UserId);
    
    NavigationManager.NavigateTo("/admin/accounts");
}
```

**Data Flow:**
- Source: `UserId` parameter (route parameter, line 25)
- Path: DeleteAccount() method invoked by button click
- Sink: `AccountService.DeleteAccountAsync(UserId)` at line 37
- Missing Check: No authorization verification in the handler

The authorization is incorrectly enforced only at the UI rendering level via `<AuthorizeView>`, not at the method execution level.

## Fix

### File: AdminAccountPanel.razor

```csharp
@page "/admin/accounts/{UserId}"
@using Microsoft.AspNetCore.Components.Authorization
@inject IAccountService AccountService
@inject NavigationManager NavigationManager
@inject AuthenticationStateProvider AuthenticationStateProvider

<h3>Account: @UserId</h3>

<AuthorizeView Roles="Admin">
    <Authorized>
        <p>Signed in as @context.User.Identity?.Name.</p>
        <button class="btn btn-danger" @onclick="DeleteAccount" disabled="@isDeleting">Delete Account</button>
    </Authorized>
    <NotAuthorized>
        <p>You do not have permission to manage this account.</p>
    </NotAuthorized>
</AuthorizeView>

@if (isDeleting)
{
    <p>Deleting account...</p>
}

@code {
    [Parameter]
    public string UserId { get; set; } = string.Empty;

    private bool isDeleting;

    private async Task DeleteAccount()
    {
        // Authorization check: Verify the user has Admin role before proceeding
        var authState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
        if (!authState.User.IsInRole("Admin"))
        {
            throw new UnauthorizedAccessException("Only administrators can delete accounts.");
        }

        isDeleting = true;

        await AccountService.DeleteAccountAsync(UserId);

        NavigationManager.NavigateTo("/admin/accounts");
    }
}
```

## Explanation

The fix adds a server-side authorization check inside the `DeleteAccount()` event handler before the sensitive operation executes.

**Changes made:**
1. **Inject AuthenticationStateProvider** (line 5) - Provides access to the current user's authentication state and claims
2. **Add authorization check** (lines 39-42) - Inside the method, before any sensitive operation:
   - Call `GetAuthenticationStateAsync()` to retrieve the current user's authentication state
   - Check if the user has the Admin role using `IsInRole("Admin")`
   - Throw `UnauthorizedAccessException` if the user lacks the required role

This closes the vulnerability by enforcing authorization at the method execution level, not just the UI rendering level. An attacker who attempts to invoke the handler directly will now receive an exception rather than being able to delete accounts without authorization.

The fix preserves the existing authorization model (admin-only access) and does not introduce new vulnerabilities. `AuthenticationStateProvider` and `UnauthorizedAccessException` are part of the standard ASP.NET Core Blazor and .NET frameworks respectively, requiring no additional dependencies.

## Behaviour changes

**Authorized users (admins):**
- No change: The method behavior is identical for users with the Admin role. They can still delete accounts as before.

**Unauthorized users (non-admins):**
- Before fix: The delete button is hidden in the UI, but the `DeleteAccount()` method can still be invoked directly.
- After fix: An `UnauthorizedAccessException` is thrown when attempting to invoke the handler without the Admin role, preventing account deletion.

**API compatibility:**
- No breaking changes to the component's contract or public interface.
- The method signature remains the same; only internal authorization logic is added.
