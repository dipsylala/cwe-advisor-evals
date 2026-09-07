## Verdict

Exploitable. Any authenticated user can delete any message by calling `DeleteMessage(messageId)` with an arbitrary message ID. The hub's class-level `[Authorize]` attribute verifies only that the caller is authenticated; it does not check whether the caller owns or has permission to delete the specific message being deleted. The authorization check required by CWE-862 is entirely absent.

## Source

The `messageId` parameter passed to the `DeleteMessage` hub method originates from the caller (client-side SignalR invocation), which is untrusted. The parameter is passed directly to `_messageStore.DeleteMessageAsync(messageId)` with no authorization check intervening.

## Fix

**Vulnerable code:**
```csharp
public async Task DeleteMessage(int messageId)
{
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    await _messageStore.DeleteMessageAsync(messageId);
    await Clients.All.SendAsync("MessageDeleted", messageId);
}
```

**Fixed code:**
```csharp
public async Task DeleteMessage(int messageId)
{
    // Load the message to verify ownership
    var message = await _messageStore.GetMessageAsync(messageId);
    
    if (message == null)
    {
        throw new HubException("Message not found");
    }
    
    // Get current user ID
    var userId = Context.User?.Identity?.Name;
    if (string.IsNullOrEmpty(userId))
    {
        throw new HubException("User not authenticated");
    }
    
    // Authorization: verify the current user owns the message
    if (message.OwnerId != userId)
    {
        throw new HubException("Not authorized to delete this message");
    }
    
    // Now safe to delete
    await _messageStore.DeleteMessageAsync(messageId);
    await Clients.All.SendAsync("MessageDeleted", messageId);
}
```

## Explanation

The fix adds a resource-based authorization check before deletion. It loads the message from the store, retrieves the current user's identity from the SignalR connection context, and verifies that the user owns the message before calling the delete operation. If the message does not exist, the user is not authenticated, or the user does not own the message, a `HubException` is thrown to reject the request. This prevents an authenticated user from deleting messages belonging to others. The check follows the CWE-862 guidance principle that authorization must verify both authentication and resource ownership, not just that the caller is logged in.

## Behaviour changes

- **Added method call** `await _messageStore.GetMessageAsync(messageId)`: Retrieves the message record to enable ownership verification. This adds one database/store query per `DeleteMessage` invocation. Justification: Required to obtain the message's owner ID for the authorization check.
- **Added null check** on the retrieved message and thrown `HubException` if null: Distinguishes "message not found" from "not authorized", providing clearer feedback and matching the semantics of the CWE-862 remediation (fail closed with explicit denial). Justification: Resource existence and ownership are separate concerns; checking both provides the correct error signal.
- **Added authentication check** on `Context.User?.Identity?.Name`: Defensive check to confirm the current user identity is available, even though SignalR has `[Authorize]` at the class level. Thrown `HubException` if identity is unavailable. Justification: Ensures the authorization decision is based on a valid identity; fails closed.
- **Added authorization comparison** `message.OwnerId != userId`: Verifies the authenticated user owns the resource before permitting deletion. Thrown `HubException` if ownership check fails. Justification: This is the core fix for CWE-862; without it, any authenticated user can delete any message.
