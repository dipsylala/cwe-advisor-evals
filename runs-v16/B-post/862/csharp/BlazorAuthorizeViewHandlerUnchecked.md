## Verdict

**Confirmed** - CWE-862 (Missing Authorization). The `AuthorizeView` component guards rendering of the "Delete Account" button but does not enforce authorization on the event handler itself. The `DeleteAccount()` method can be invoked by any authenticated user, not only admins, because client-side UI controls are not security boundaries. An attacker who can reach the component can delete any account by calling the handler directly or modifying the component's rendered state.

## Source

**File:** `AdminAccountPanel.razor`  
**Line:** 37  
**Vulnerable code:**
```csharp
await AccountService.DeleteAccountAsync(UserId);
```

The event handler `DeleteAccount()` lacks an authorization check. The `AuthorizeView Roles="Admin"` on lines 8–16 only determines what renders; it does not prevent the handler from executing.

## Fix

**Inject `IAuthorizationService`** at the top of the component:
```csharp
@inject IAuthorizationService AuthorizationService
@inject AuthenticationStateProvider AuthenticationStateProvider
```

**Add authorization check in the `DeleteAccount()` method** before the delete operation:
```csharp
private async Task DeleteAccount()
{
    isDeleting = true;

    // Check authorization: verify the user holds the Admin role
    var authState = await AuthenticationStateProvider.GetAuthenticationStateAsync();
    var authResult = await AuthorizationService.AuthorizeAsync(authState.User, "AdminOnly");
    
    if (!authResult.Succeeded)
    {
        isDeleting = false;
        return;
    }

    await AccountService.DeleteAccountAsync(UserId);

    NavigationManager.NavigateTo("/admin/accounts");
}
```

**Define the "AdminOnly" policy in `Program.cs`** (if not already defined):
```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => 
        policy.RequireRole("Admin"));
});
```

## Explanation

The vulnerability occurs because `AuthorizeView` is a rendering control, not a security boundary. It hides UI elements from unauthorized users but does not prevent direct invocation of the event handler through client-side code modification, browser DevTools, or direct API calls.

The fix adds an explicit server-side authorization check using `IAuthorizationService.AuthorizeAsync()` inside the event handler. This check verifies the authenticated user holds the "Admin" role before the deletion proceeds. If authorization fails, the handler exits early and returns no error response, preventing unauthorized deletion.

This pattern—authorization check inside the handler, not just in the UI—ensures protection regardless of how the method is invoked.

## Behaviour changes

- **Authorized users (Admin role):** Event handler executes as before; account is deleted and user is redirected.
- **Unauthorized users:** Event handler exits after the authorization check fails; no deletion occurs; no error message is displayed to the caller (silent failure). If a more explicit response is desired, replace the `return` with `NavigationManager.NavigateTo("/access-denied")` or throw an exception caught by the error boundary.
- **Unauthenticated users:** If the user is not authenticated, `authState.User.Identity?.IsAuthenticated` is false and authorization fails; the handler exits.

The `isDeleting` flag is reset to `false` on authorization failure so the UI does not display "Deleting account..." indefinitely.
