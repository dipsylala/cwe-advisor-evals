## Verdict
CONFIRMED

## Source
```csharp
public async Task DeleteMessage(int messageId)
{
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    await _messageStore.DeleteMessageAsync(messageId);
    await Clients.All.SendAsync("MessageDeleted", messageId);
}
```

The `[Authorize]` attribute on the class checks only authentication (user is logged in), not authorization (user has permission to delete this specific message). Any authenticated user can delete any message by knowing its ID.

## Fix
```csharp
public async Task DeleteMessage(int messageId)
{
    var userId = Context.UserIdentifier ?? Context.User?.Identity?.Name ?? "unknown";
    
    var message = await _messageStore.GetMessageAsync(messageId);
    if (message == null)
    {
        throw new HubException("Message not found.");
    }
    
    if (message.UserId != userId)
    {
        throw new HubException("Unauthorized: You do not have permission to delete this message.");
    }
    
    await _messageStore.DeleteMessageAsync(messageId);
    await Clients.All.SendAsync("MessageDeleted", messageId);
}
```

## Explanation
The fix adds ownership validation before allowing message deletion. It retrieves the message, verifies it exists, and checks that the current user is the message's owner. Only the owner can delete their own messages. Unauthorized deletion attempts throw `HubException`, which SignalR handles as a hub error sent back to the client. This transforms the method from a class-level authentication check (anyone who can connect) to per-method authorization (only owners can delete their own messages).
