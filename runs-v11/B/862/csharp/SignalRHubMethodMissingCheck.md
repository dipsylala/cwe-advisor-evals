## Verdict
exploitable

## Source
`messageId` parameter supplied by an authenticated caller with no restriction on which messages they may delete

## Fix

**Vulnerable code:**
```csharp
public async Task DeleteMessage(int messageId)
{
    // No authorization check: any authenticated user can delete any message
    await _messageStore.DeleteMessageAsync(messageId);
    await Clients.All.SendAsync("MessageDeleted", messageId);
}
```

**Fixed code:**
```csharp
private readonly IAuthorizationService _authorizationService;

public ChatHub(IChatMessageStore messageStore, IAuthorizationService authorizationService)
{
    _messageStore = messageStore;
    _authorizationService = authorizationService;
}

public async Task DeleteMessage(int messageId)
{
    var message = await _messageStore.GetMessageAsync(messageId);
    if (message == null)
    {
        throw new HubException("Message not found.");
    }
    
    var authResult = await _authorizationService.AuthorizeAsync(Context.User, message, "CanDeleteMessage");
    if (!authResult.Succeeded)
    {
        throw new HubException("Not authorized to delete this message.");
    }
    
    await _messageStore.DeleteMessageAsync(messageId);
    await Clients.All.SendAsync("MessageDeleted", messageId);
}
```

**Program.cs configuration (required):**
```csharp
services.AddAuthorization(options =>
{
    options.AddPolicy("CanDeleteMessage", policy =>
        policy.Requirements.Add(new MessageOwnershipRequirement()));
});
services.AddSingleton<IAuthorizationHandler, MessageOwnershipHandler>();
```

**Authorization handler:**
```csharp
public class MessageOwnershipRequirement : IAuthorizationRequirement { }

public class MessageOwnershipHandler : AuthorizationHandler<MessageOwnershipRequirement, ChatMessage>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MessageOwnershipRequirement requirement,
        ChatMessage message)
    {
        if (message.UserId == context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value)
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}
```

## Explanation
The fix adds resource-based authorization by loading the message from the store and verifying the authenticated user owns it before allowing deletion. The `IAuthorizationService.AuthorizeAsync` call passes the specific message entity and a policy (`CanDeleteMessage`) to a custom `AuthorizationHandler` that compares the message's `UserId` against the caller's identity claim. This closes the vulnerability by ensuring every `DeleteMessage` call checks not just authentication but also that the caller has explicit permission to delete that specific message. Ownership verification happens server-side before any state change, following the centralized authorization pattern already used in the ASP.NET Core application.

## Behaviour changes
- The method now loads the message before deletion to verify ownership (adds a database call)
- The method throws `HubException` instead of proceeding if the message is not found or the caller does not own it (appropriate for SignalR, which returns errors to the caller rather than HTTP status codes)
- Requires dependency injection of `IAuthorizationService` into the hub constructor
- Requires configuration of the `CanDeleteMessage` policy and `MessageOwnershipHandler` in `Program.cs`
