## Verdict

Exploitable. An authenticated user without admin role can invoke the `admin:broadcastMessage` event handler and broadcast to all connected users, bypassing the intended admin-only restriction.

## Source

User-supplied event payload in the `admin:broadcastMessage` event handler (line 52). Client sends an event with a `text` property without any authorization check.

## Fix

**Vulnerable code:**
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
  // Authorization: only users with 'admin' role can broadcast
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

The fix adds an explicit role-based authorization check at the start of the `admin:broadcastMessage` event handler. Socket.IO middleware registered with `io.use()` runs once per connection and authenticates the user, but does not enforce per-event authorization. Since the broadcast is an admin-only action, the handler must check that `socket.user.role` is `'admin'` before allowing the operation. The check is placed before any payload validation so that unauthorized callers are rejected immediately. This follows the guidance principle: authentication (who the caller is) and authorization (what they may do) are separate checks, and every sensitive action must have an explicit authorization gate.

## Behaviour changes

None. The fix preserves the original contract: authorized (admin) users receive the same broadcast behavior; unauthorized users silently return without error (matching the existing validation pattern for malformed payloads at line 38-40). No arguments, return values, or observable side effects change except the authorization control itself.
