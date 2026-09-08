## Verdict

CWE-862 (Missing Authorization) is confirmed. The `DeleteMessage` method accepts an authenticated user but performs no authorization check to verify the caller is permitted to delete the specific message. Any authenticated user can delete any message.

## Source

File: ChatHub.cs, line 28–33 (the `DeleteMessage` method)

The vulnerability is that the method directly calls `_messageStore.DeleteMessageAsync(messageId)` without verifying the caller owns or has permission to delete the message. The class-level `[Authorize]` attribute ensures only authenticated users can connect to the hub, but it makes no statement about which individual messages a caller may delete.

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
            {
                throw new HubException("Message not found.");
            }

            // Authorization: only the message owner or an administrator can delete it
            if (message.UserId != userId && !Context.User.IsInRole("Admin"))
            {
                throw new HubException("Unauthorized to delete this message.");
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

The fix adds two authorization checks before deletion:

1. **Retrieve the message** to access its metadata (owner identity).
2. **Verify ownership or admin role**: Only the user who created the message (message owner) or a user with the Admin role is permitted to delete it. If neither condition is true, a `HubException` is thrown, which SignalR propagates to the client as an error.

This follows the principle that authorization decisions must be made per-resource: authentication (the `[Authorize]` attribute) confirms the caller's identity, but authorization (the ownership/role check) confirms the caller's right to act on that specific message. Without per-resource authorization, any authenticated user could delete messages belonging to others.
