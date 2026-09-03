## Verdict

Real vulnerability confirmed. The `DeleteMessage` method performs a sensitive action (message deletion) without verifying the caller owns or has permission to delete the target message. The `[Authorize]` attribute on the hub class verifies only authentication (that the caller is logged in), not authorization (what they may do).

## Source

File: `evals/cases/862/csharp/SignalRHubMethodMissingCheck/ChatHub.cs`
Line: 31 (the `DeleteMessageAsync` call)

The vulnerable method:
```csharp
public async Task DeleteMessage(int messageId)
{
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    await _messageStore.DeleteMessageAsync(messageId);
    await Clients.All.SendAsync("MessageDeleted", messageId);
}
```

Any authenticated user can delete any message by guessing or enumerating message IDs, regardless of ownership.

## Fix

Add a resource-based authorization check before deletion. Load the message, verify the caller owns it, and delete only if authorized.

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
        throw new HubException("Unauthorized: You do not own this message.");
    }
    
    await _messageStore.DeleteMessageAsync(messageId);
    await Clients.All.SendAsync("MessageDeleted", messageId);
}
```

## Explanation

The fix adds a resource-level ownership check before deletion. After loading the message, the method compares its owner (`message.UserId`) against the authenticated caller's identity (`Context.UserIdentifier`). Only the message owner is permitted to delete it. An unauthorized caller receives a `HubException` rather than silent denial or a fake success. This aligns with the CWE-862 guidance: check both the action (caller is authenticated) and the resource (caller owns this specific record). For SignalR hubs, a thrown `HubException` is returned as an error to the client instead of an HTTP status code, which is the standard failure mode for hub methods.

## Behaviour changes

- **Before fix**: Any authenticated user can delete any message by calling `DeleteMessage(messageId)` with any ID.
- **After fix**: Only the message owner can delete their own message. An unauthenticated caller cannot connect to the hub (the `[Authorize]` attribute on the class). An authenticated but unauthorized caller receives a `HubException` with message "Unauthorized: You do not own this message." A non-existent message also returns a `HubException` with "Message not found." to avoid leaking whether the message exists.
