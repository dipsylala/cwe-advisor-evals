## Verdict

**CWE-862: Missing Authorization** - Confirmed. The `DeleteMessage` hub method performs a sensitive operation without verifying that the authenticated caller owns or is authorized to delete the specific message identified by `messageId`. The hub-level `[Authorize]` attribute only validates authentication at connection time; it does not authorize operations on individual resources. An authenticated user can delete any message by guessing or enumerating `messageId` values.

## Source

The vulnerability originates from the `messageId` parameter passed by the caller to the `DeleteMessage(int messageId)` method at line 28. The parameter is used directly as the message to delete without any ownership or permission check.

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
            var userId = Context.UserIdentifier ?? Context.User?.Identity?.Name ?? "unknown";
            var message = await _messageStore.GetMessageAsync(messageId);
            
            if (message == null)
                throw new HubException("Message not found");
            
            if (message.UserId != userId)
                throw new HubException("Unauthorized to delete this message");
            
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

The fix adds a resource-based authorization check that verifies the current user owns the message before allowing deletion. It extracts the authenticated user's identifier from the SignalR context (using the same pattern as `SendMessage`), loads the message via `GetMessageAsync`, and compares the message's owner to the authenticated user. If the message does not exist, it throws `HubException("Message not found")`. If the message belongs to a different user, it throws `HubException("Unauthorized to delete this message")`. Only if both checks pass does the deletion proceed.

This follows the CWE-862 remediation principle: "For actions on a specific record, verify the caller owns or has a granted relationship to it, not just that they hold the right role." SignalR hub methods return errors to the caller when an exception is thrown, rather than HTTP status codes, so `HubException` is the appropriate mechanism to signal authorization failure.

## Behaviour changes

- The method now validates resource ownership before deletion. Authenticated users can only delete messages they own.
- Callers attempting to delete messages they do not own will receive a `HubException` with message "Unauthorized to delete this message".
- Callers attempting to delete non-existent messages will receive a `HubException` with message "Message not found".
- The method requires `IChatMessageStore` to have a `GetMessageAsync(int messageId)` method that returns a message with a `UserId` property. If the interface does not currently expose this method, it must be added to support the ownership check.
