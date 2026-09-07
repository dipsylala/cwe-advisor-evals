## Verdict

CONFIRMED - Missing Authorization on sensitive operation.

## Source

AdminAccountPanel.razor, line 37, in event handler `DeleteAccount()`.

The handler is invoked by a button rendered inside `<AuthorizeView Roles="Admin">`. However, `AuthorizeView` controls rendering only; it does not enforce authorization on handler invocation. An attacker can:
1. Directly invoke the handler via JavaScript console
2. Call the underlying API endpoint without the UI control
3. Delete any account by manipulating the `UserId` parameter

No server-side authorization check guards the `AccountService.DeleteAccountAsync()` call.

## Fix

### File: AdminAccountPanel.razor

```csharp
@page "/admin/accounts/{UserId}"
@using Microsoft.AspNetCore.Components.Authorization
@inject IAccountService AccountService
@inject NavigationManager NavigationManager
@inject AuthenticationStateProvider AuthenticationStateProvider
@inject IAuthorizationService AuthorizationService

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
        // Perform server-side authorization check before executing sensitive action
        var authState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
        var authResult = await AuthorizationService.AuthorizeAsync(authState.User, "AdminOnly");
        
        if (!authResult.Succeeded)
        {
            // Authorization failed, deny the request
            NavigationManager.NavigateTo("/access-denied");
            return;
        }

        isDeleting = true;

        await AccountService.DeleteAccountAsync(UserId);

        NavigationManager.NavigateTo("/admin/accounts");
    }
}
```

## Explanation

The fix adds a mandatory server-side authorization check inside the `DeleteAccount()` event handler before the sensitive operation executes. It:

1. **Injects authorization services**: `AuthenticationStateProvider` retrieves the current user's claims, and `IAuthorizationService` evaluates the authorization policy.
2. **Checks authorization**: `AuthorizeAsync(user, "AdminOnly")` verifies the authenticated caller holds the required authorization. This policy must be defined in `Program.cs` via `AddAuthorization`.
3. **Fails closed**: If authorization fails, the handler redirects to an access-denied page and returns without calling `DeleteAccountAsync()`, preventing execution.
4. **Preserves the UI control**: The `AuthorizeView` remains for rendering, improving UX by not showing the button to unprivileged users, but no longer serves as the sole defense.

The fix eliminates the gap between "button is hidden" and "operation is allowed". The check now runs server-side for every invocation of the handler, regardless of how the caller reached it.

## Behaviour changes

- **New runtime dependency**: Requires `AuthenticationStateProvider` and `IAuthorizationService` to be registered in the DI container (standard in ASP.NET Core).
- **New authorization policy**: Requires an "AdminOnly" policy to be defined in `Program.cs` via `AddAuthorization()`. If not defined, authorization will fail and requests will be denied.
- **Redirection on denial**: Unauthorized callers are redirected to `/access-denied` instead of silently failing or showing a UI error. This maintains the same security posture as attribute-based authorization on HTTP endpoints.
- **No breaking changes to success path**: Authorized admins continue to delete accounts as before; the fix only blocks unauthorized callers.
