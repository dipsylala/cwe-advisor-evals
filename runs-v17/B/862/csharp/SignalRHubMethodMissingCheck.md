## Verdict

**CONFIRMED - Missing Authorization**

The `DeleteMessage` method in the SignalR hub accepts a message ID without verifying that the authenticated caller owns the message. The hub's `[Authorize]` attribute confirms the connection is from an authenticated user, but this connection-time check does not apply to individual method invocations. An authenticated attacker can delete any message by guessing or enumerating message IDs.

## Source

**File:** `ChatHub.cs`, line 31  
**Method:** `DeleteMessage(int messageId)`

The hub method receives a message ID from an untrusted caller and passes it directly to `_messageStore.DeleteMessageAsync(messageId)` without:
1. Loading the message to determine its owner
2. Verifying the current user is the message author
3. Returning an error if ownership does not match

The data flow: untrusted caller input (messageId) → sink (`DeleteMessageAsync`) with no ownership check.

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

            // Load the message to check authorization (resource-based ownership)
            var message = await _messageStore.GetMessageAsync(messageId);

            // Authorization: verify the caller owns this message before deletion
            if (message == null || message.AuthorUserId != userId)
            {
                throw new HubException("Not authorized to delete this message");
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

The fix adds resource-based authorization to the `DeleteMessage` hub method by:

1. **Retrieving the current user ID** - extract the authenticated user's identity (same pattern already used in `SendMessage`)
2. **Loading the message** - call `GetMessageAsync` to fetch the message and its `AuthorUserId` property
3. **Verifying ownership** - compare the message's `AuthorUserId` against the current user's ID
4. **Enforcing the check** - throw `HubException` if the message does not exist or the caller does not own it, preventing deletion
5. **Proceeding only if authorized** - the delete and broadcast happen only after the ownership check succeeds

This follows the C# guidance for SignalR: hub methods must add resource-level checks because the hub's `[Authorize]` attribute only authenticates the connection, not individual operations. The `HubException` is the appropriate error signal for a failed authorization in a SignalR context; it returns an error to the calling client rather than an HTTP status code.

The fix closes the vulnerability by making deletion conditional on ownership, eliminating the attack path where an authenticated user guesses or enumerates message IDs to delete messages authored by others.

## Behaviour changes

**Authorized behaviour:** A user can still delete their own messages; the method returns successfully and broadcasts the deletion to all clients as before.

**Unauthorized behaviour:** When a user attempts to delete a message they do not own, or when a message ID does not exist, the method now throws `HubException("Not authorized to delete this message")` instead of silently deleting it. The client receives this exception and the deletion does not occur; the message is not removed from storage and no broadcast is sent.

**No change to signed-in requirement:** The connection-level `[Authorize]` requirement remains; unauthenticated users are still rejected at connection time.
