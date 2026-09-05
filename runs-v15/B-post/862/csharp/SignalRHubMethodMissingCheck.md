## Verdict

Exploitable

## Source

The `messageId` parameter in the `DeleteMessage` hub method at line 28, supplied by any authenticated SignalR client.

## Fix

**Vulnerable code (lines 28–33):**

```csharp
public async Task DeleteMessage(int messageId)
{
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    await _messageStore.DeleteMessageAsync(messageId);
    await Clients.All.SendAsync("MessageDeleted", messageId);
}
```

**Fixed code (lines 28–40):**

```csharp
public async Task DeleteMessage(int messageId)
{
    var message = await _messageStore.GetMessageAsync(messageId);
    if (message == null)
    {
        throw new HubException("Message not found.");
    }
    
    var currentUserId = Context.UserIdentifier;
    if (message.UserId != currentUserId)
    {
        throw new HubException("Not authorized to delete this message.");
    }
    
    await _messageStore.DeleteMessageAsync(messageId);
    await Clients.All.SendAsync("MessageDeleted", messageId);
}
```

## Explanation

The original `DeleteMessage` method accepts a `messageId` from an authenticated client but performs no ownership check before deletion. The class-level `[Authorize]` attribute only verifies that the caller is authenticated; it does not restrict which messages a user may delete. Any authenticated user can delete any message by supplying its ID. The fix loads the message first to check its owner against the authenticated `Context.UserIdentifier`. If the message is not found or is owned by a different user, a `HubException` is thrown to return an error to the caller. Only if the user owns the message does the deletion proceed. This enforces resource-level authorization on every deletion, closing the gap between authentication (who is this user) and authorization (what may this user do).

## Behaviour changes

Added call to `_messageStore.GetMessageAsync(messageId)` before the delete. This introduces a database read per deletion where the original code had none. Added null check and ownership verification with `HubException` throws for unauthorized access. These changes are necessary to enforce the authorization check: without loading the message first, the user's ownership cannot be determined. The additional database call is the cost of verifying authorization on a resource-specific operation.
