## Verdict

**Confirmed.** The `DeleteMessage` method lacks per-resource authorization, allowing any authenticated user to delete messages belonging to other users.

## Source

```csharp
public async Task DeleteMessage(int messageId)
{
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    await _messageStore.DeleteMessageAsync(messageId);
    await Clients.All.SendAsync("MessageDeleted", messageId);
}
```

The `[Authorize]` attribute on the class enforces authentication (connection-level access control) but does not enforce authorization at the method level. The method accepts a message ID and deletes it without verifying that the caller owns or has permission to delete that message.

## Fix

```csharp
public async Task DeleteMessage(int messageId)
{
    var message = await _messageStore.GetMessageAsync(messageId);
    
    if (message == null)
    {
        throw new HubException("Message not found.");
    }
    
    var userId = Context.UserIdentifier ?? Context.User?.Identity?.Name ?? "unknown";
    if (message.UserId != userId)
    {
        throw new UnauthorizedAccessException("You are not authorized to delete this message.");
    }
    
    await _messageStore.DeleteMessageAsync(messageId);
    await Clients.All.SendAsync("MessageDeleted", messageId);
}
```

## Explanation

The fix adds two authorization checks before deleting the message:

1. **Existence check:** Retrieve the message by ID. If it does not exist, throw `HubException` with a descriptive error. This prevents revealing whether a message ID exists to unauthorized callers.

2. **Ownership check:** Compare the message's owner (`message.UserId`) to the current caller's identity (`Context.UserIdentifier` or extracted from `Context.User`). Only proceed if the caller owns the message. If ownership does not match, throw `UnauthorizedAccessException`, which SignalR converts into a client-side error.

This implements per-resource authorization—each resource (message) is checked to ensure the caller has permission to act on it—rather than relying on connection-level authentication alone.

The `IChatMessageStore` interface is assumed to expose a `GetMessageAsync(messageId)` method that returns a message object containing a `UserId` field. If the store lacks this method, add it or retrieve the message through another query path before the authorization check.
