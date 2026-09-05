## Verdict

The finding is valid. Line 52 registers a Socket.IO event handler for `admin:broadcastMessage` that performs a sensitive action (broadcasting to all connected users) without verifying the authenticated caller holds the admin role. The initial authentication via `io.use()` confirms the caller has a valid JWT, but `io.use()` runs once per connection, not per event, so the handler must add an explicit per-event authorization check.

## Source

Socket.IO event handler at line 52 in `chatServer.js`.

The event handler receives an authenticated socket with `socket.user` containing `id`, `username`, and `role`. The handler accepts a `payload` with user-controlled `text` and broadcasts it to all connected clients via `io.emit()`.

Authentication is established earlier (lines 15-31) via `io.use()` middleware that decodes the JWT and attaches the user object. This middleware runs once at connection and does not re-authorize per event.

## Fix

Add an explicit role check in the event handler before performing the broadcast:

```javascript
socket.on('admin:broadcastMessage', (payload) => {
  // Authorization: require admin role
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

Socket.IO event handlers do not support middleware chaining per-event (unlike Express routes). The `io.use()` middleware runs once when the socket connects, confirming the caller is authenticated, but it cannot enforce per-event authorization for different sensitivity levels.

The fix adds an explicit, in-handler authorization check: `if (socket.user.role !== 'admin')`. Since the `socket.user` object is already populated by the connection-time middleware and contains the role field, this check verifies the caller holds admin privilege before allowing the broadcast. Non-admin users silently exit the handler, preventing unauthorized broadcast.

This follows the JavaScript guidance principle: "Apply authorization middleware at the router or route level... For Socket.IO, an event handler needs... an in-handler check" when per-event middleware is unavailable.

## Behaviour changes

- Non-admin authenticated users who emit `admin:broadcastMessage` will no longer succeed; the handler returns without broadcasting.
- Admin users experience no change; the check passes and the broadcast proceeds as before.
- No change to socket connection, disconnection, or other event handlers.
- No change to the JWT verification or session management flow.
