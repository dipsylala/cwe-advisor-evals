## Verdict

Confirmed. `[Authorize]` on `ChatHub` only proves the caller has an authenticated connection; it says nothing about which specific chat message that caller may act on. `DeleteMessage` takes a caller-supplied `messageId` and passes it straight to `_messageStore.DeleteMessageAsync(messageId)` with no check that the message belongs to the caller (or that the caller otherwise has permission to remove it). Any authenticated user can delete any other user's message simply by guessing or enumerating message ids. This is a missing object-level authorization check (CWE-862).

## Source

`messageId`, the `int` parameter of the client-invocable hub method `DeleteMessage(int messageId)` (line 28), is attacker-controlled - any connected client can invoke this method with any id. It flows unchecked into the sink `_messageStore.DeleteMessageAsync(messageId)` (line 31), which deletes the message with no ownership or role check performed anywhere in between.

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
            var userId = Context.UserIdentifier ?? Context.User?.Identity?.Name;
            if (string.IsNullOrEmpty(userId))
            {
                throw new HubException("You must be signed in to delete messages.");
            }

            // The store performs the ownership/role check as part of the same
            // operation that deletes the row, so there is no separate
            // fetch-then-delete window for the message's owner to change
            // between the check and the sink.
            var isModerator = Context.User?.IsInRole("Moderator") ?? false;
            var deleted = await _messageStore.DeleteMessageAsync(messageId, userId, isModerator);
            if (!deleted)
            {
                throw new HubException("You are not authorized to delete this message.");
            }

            await Clients.All.SendAsync("MessageDeleted", messageId);
        }

        public async Task JoinRoom(string roomId)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, roomId);
        }
    }
}
```

### File: IChatMessageStore.cs
```csharp
using System.Threading.Tasks;

namespace ChatApp.Hubs
{
    public interface IChatMessageStore
    {
        Task<object> AddMessageAsync(string roomId, string userId, string text);

        // Deletes the message identified by messageId only if requestingUserId
        // is its author, or isModerator is true. Returns false - without
        // deleting anything - if the message does not exist or the caller is
        // not permitted to remove it. Implementations must enforce this as
        // part of the delete itself (e.g. a single "DELETE ... WHERE id = @id
        // AND (author_id = @requestingUserId OR @isModerator)" statement, or
        // an equivalent transaction), not as a separate lookup performed
        // before an unconditional delete, so the authorization decision and
        // the mutation cannot drift apart.
        Task<bool> DeleteMessageAsync(int messageId, string requestingUserId, bool isModerator);
    }
}
```

## Explanation

The vulnerability is a classic IDOR/missing-object-authorization gap: `[Authorize]` at the hub level confirms *who* the caller is once, at connection time, but `DeleteMessage` never confirms that the caller is entitled to delete *this particular* message. Because the only input to the sink is a bare integer id, closing the gap requires the deletion itself to be conditioned on the caller's identity relative to the message's owner - that data isn't available anywhere in the hub, so the check has to happen where the message's authorship is actually known: the store.

The fix changes `DeleteMessageAsync` to take the requesting user's id and role status alongside the message id, and to return whether the delete actually happened. The hub then treats a `false` result as "not authorized" and raises a `HubException` before notifying any clients, so `Clients.All.SendAsync("MessageDeleted", ...)` only ever fires for a deletion that really occurred. Folding the ownership check into the same operation that performs the delete (rather than fetching the message first, checking it in the hub, and then deleting) removes a fetch-then-act race and matches how an authoritative row-level check is normally expressed in SQL or an equivalent atomic store operation - the caller-supplied id can no longer be used to remove a message that does not belong to them, and a `Moderator` caller (or whatever the application's existing elevated role is) retains the ability to moderate any message.
