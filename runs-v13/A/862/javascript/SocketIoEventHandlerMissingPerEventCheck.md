## Verdict
CONFIRMED: Missing authorization check for privileged admin operation.

## Source
The `admin:broadcastMessage` event handler at line 52 broadcasts a message to all connected clients without verifying that the caller holds admin privileges. While the connection middleware validates the JWT token and attaches the decoded user to the socket (including role), it does not enforce authorization for individual events. An authenticated user with any role can invoke this handler to broadcast messages server-wide.

## Fix
Add a role check at the start of the `admin:broadcastMessage` handler to reject non-admin callers:

```javascript
socket.on('admin:broadcastMessage', (payload) => {
  if (socket.user.role !== 'admin') {
    return;
  }
  const { text } = payload || {};
  if (typeof text !== 'string' || !text.trim()) {
    return;
  }
  io.emit('chat:announcement', {
    from: socket.user.username,
    text: text.slice(0, 2000),
    sentAt: Date.now(),
  });
});
```

## Explanation
Authentication (validating identity via the JWT token) is enforced at the connection level and is sufficient to confirm the user exists. Authorization (confirming the user has permission for a specific action) must be enforced per-event for privileged operations.

The `admin:broadcastMessage` handler performs a sensitive action—broadcasting to the entire server—that should be restricted to users with the `admin` role. The fix adds a guard clause that checks `socket.user.role` before proceeding with the broadcast. Non-admin users are silently rejected (consistent with the payload validation pattern already in use), ensuring only authorized callers can trigger server-wide announcements.
