## Verdict

Confirmed. The `DeleteMessage` method lacks authorization to verify the caller owns the message before deletion. The class-level `[Authorize]` attribute only enforces authentication (connection-time identity check) and does not govern which messages a user may delete.

## Source

**File**: ChatHub.cs, line 31  
**Sink**: `await _messageStore.DeleteMessageAsync(messageId);`  
**Data flow**: The `messageId` parameter (user-supplied, untrusted) flows directly to the delete operation without resource ownership verification.

**Vulnerable code**:
```csharp
public async Task DeleteMessage(int messageId)
{
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    await _messageStore.DeleteMessageAsync(messageId);
    await Clients.All.SendAsync("MessageDeleted", messageId);
}
```

An authenticated user can delete any message by guessing or enumerating message IDs. The hub authorizes only at connection time; no per-method resource-level check exists.

## Fix

### File: ChatHub.cs

```csharp
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace ChatApp.Hubs
{
    // Only authenticated users may open a connection to this hub, but that
    // check runs once at connection time and says nothing about which
    // individual chat messages a given caller is allowed to act on.
    [Authorize]
    public class ChatHub : Hub
    {
        private readonly IChatMessageStore _messageStore;

        public ChatHub(IChatMessageStore messageStore)
        {
            _messageStore = messageStore;
        }

        public async Task SendMessage(string roomId, string text)
        {
            var userId = Context.UserIdentifier ?? Context.User?.Identity?.Name ?? "unknown";
            var message = await _messageStore.AddMessageAsync(roomId, userId, text);
            await Clients.Group(roomId).SendAsync("ReceiveMessage", message);
        }

        public async Task DeleteMessage(int messageId)
        {
            // Load the message to verify ownership before deletion
            var message = await _messageStore.GetMessageAsync(messageId);
            
            if (message == null)
            {
                throw new HubException("Message not found.");
            }

            var currentUserId = Context.UserIdentifier ?? Context.User?.Identity?.Name;
            
            // Verify the current user owns the message before allowing deletion
            // CWE-862 fix: Check resource-level access (message ownership)
            if (message.UserId != currentUserId)
            {
                throw new HubException("Unauthorized: You can only delete your own messages.");
            }

            await _messageStore.DeleteMessageAsync(messageId);
            await Clients.All.SendAsync("MessageDeleted", messageId);
        }

        public async Task JoinRoom(string roomId)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, roomId);
        }
    }
}
```

## Explanation

The fix adds resource-based authorization to the `DeleteMessage` method by:

1. **Loading the message** - calls `_messageStore.GetMessageAsync(messageId)` to fetch the message record
2. **Verifying existence** - throws `HubException` if the message does not exist (guards against non-existent IDs)
3. **Checking ownership** - compares the message's `UserId` against the authenticated caller's identity from `Context.UserIdentifier` (or fallback to `Context.User?.Identity?.Name`)
4. **Enforcing denial** - throws `HubException` if the caller does not own the message, preventing deletion of messages authored by others

This closes the CWE-862 vulnerability by ensuring only the message author can delete their own messages. The `HubException` is the correct SignalR pattern for method-level authorization failures; it returns an error to the caller rather than an HTTP status code.

## Behaviour changes

- **Added server-side authorization check**: The method now loads and validates message ownership before deletion.
- **New exception paths**: The method throws `HubException` for missing messages and unauthorized delete attempts. Previously, both scenarios would have succeeded or failed at the store layer without user-facing authorization logic.
- **No breaking change to successful case**: Authorized deletions (owned messages) proceed identically to before.
- **Implicit contract assumption**: The fix assumes `IChatMessageStore` exposes a `GetMessageAsync(messageId)` method and that the returned message object has a `UserId` property matching the message author's identity. These assumptions align with the usage pattern in `SendMessage` and the store's `AddMessageAsync(roomId, userId, text)` signature.
