## Verdict

exploitable

## Source

The `DeleteAccount()` event handler in the Blazor component is a client-callable method that can be invoked directly by any user, regardless of authorization checks visible in the UI.

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
        isDeleting = true;

        // Server-side authorization check before executing sensitive operation
        var authState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
        var user = authState.User;

        if (!user.IsInRole("Admin"))
        {
            // User lacks required authorization; deny the request
            isDeleting = false;
            return;
        }

        await AccountService.DeleteAccountAsync(UserId);

        NavigationManager.NavigateTo("/admin/accounts");
    }
}
```

## Explanation

`AuthorizeView` controls what renders on the page, not what can be invoked. An event handler that is guarded only by `AuthorizeView` can still be called directly by an attacker through browser dev tools or by modifying the page, bypassing the UI control entirely. The fix adds a server-side authorization check inside the `DeleteAccount()` event handler itself: it retrieves the current authenticated user via `AuthenticationStateProvider`, checks whether that user holds the `Admin` role, and returns early if not. Only if the user is authorized does the code proceed to call `AccountService.DeleteAccountAsync()`. This ensures the sensitive operation is protected by server-side logic that cannot be bypassed by modifying the rendered page.

## Behaviour changes

- **Added injection**: `AuthenticationStateProvider` is injected to retrieve the current user's authentication state
- **Added authorization check**: Before invoking the sensitive operation, the handler now calls `AuthenticationStateProvider.GetAuthenticationStateAsync()` and verifies `user.IsInRole("Admin")`
- **Early return on authorization failure**: If the user lacks the required role, the handler sets `isDeleting = false` and returns without calling the service method, preventing the unauthorized deletion
- **No change to sink contract**: The service method `DeleteAccountAsync()` is still called with the same `UserId` parameter in the success case; the navigation behavior is unchanged

