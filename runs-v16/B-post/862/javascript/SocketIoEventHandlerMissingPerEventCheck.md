## Verdict

CONFIRMED - Missing authorization check on admin-only action.

## Source

The `admin:broadcastMessage` Socket.IO event handler (line 52) broadcasts to all connected clients without verifying the caller holds the admin role. The authentication middleware at `io.use()` (lines 15-31) verifies the JWT token is valid but only runs once per connection, not per event, leaving each event handler unprotected.

## Fix

**Vulnerable code (line 52-62):**

```javascript
socket.on('admin:broadcastMessage', (payload) => {
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

**Fixed code:**

```javascript
socket.on('admin:broadcastMessage', (payload) => {
  const { text } = payload || {};
  if (typeof text !== 'string' || !text.trim()) {
    return;
  }
  if (socket.user.role !== 'admin') {
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

The fix adds an explicit authorization check on line 56 (inside the handler) that denies the request if `socket.user.role` is not `'admin'`. This check runs on every invocation of the event handler, closing the gap left by the connection-time authentication middleware. The check uses the `socket.user.role` value populated by the `io.use()` middleware (line 25), which is server-controlled and decoded from the JWT token at connection time. When an unauthorized caller triggers the event, the handler returns early and the broadcast never executes, preventing privilege escalation to perform admin-only actions.

## Behaviour changes

- **Authorized callers (role='admin')**: Broadcast continues to execute unchanged. The announcement is emitted to all connected clients.
- **Unauthorized callers (role≠'admin')**: Event handler returns early, silently ignoring the request. No broadcast is sent.
- **Message structure**: No change. The emitted announcement object structure and content limits remain identical.
- **Error handling**: The fix does not change error propagation or response patterns; a denied request produces no acknowledgment to the client. This is consistent with the silent-return pattern already in use for malformed text validation (line 39).
