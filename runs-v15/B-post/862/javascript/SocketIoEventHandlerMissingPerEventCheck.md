## Verdict

**CONFIRMED** — CWE-862 (Missing Authorization). The `admin:broadcastMessage` Socket.IO event handler performs a privileged action (broadcasting a message to all connected clients) without verifying the authenticated user holds the admin role. Authentication middleware (`io.use()`) runs once at connection time and does not re-run for each event, so per-event authorization must happen inside the handler.

## Source

File: `evals/cases/862/javascript/SocketIoEventHandlerMissingPerEventCheck/chatServer.js`

Lines 52–62:
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

The handler receives `socket.user` (attached by the authentication middleware at connection time), including `socket.user.role`. However, it never checks that `role === 'admin'` before broadcasting. An authenticated user with any role—including an unprivileged one—can emit this event and send a message to all connected clients.

## Fix

Add a role check at the start of the handler. If the user lacks the admin role, return early without executing the broadcast:

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

Socket.IO authentication middleware registered with `io.use()` runs once when the socket first connects, not on each subsequent event emission. The connection handler in this code correctly stores the decoded user (including role) on `socket.user` during the initial handshake. However, the `admin:broadcastMessage` event handler assumes that `io.use()` has already protected it, which is incorrect.

The fix adds an explicit authorization check inside the handler before it performs the sensitive action (broadcasting). If `socket.user.role` is not `'admin'`, the function returns early, denying the unprivileged user access to this capability. The check uses a scalar comparison (`socket.user.role !== 'admin'`) to avoid filter-injection risks.

This approach is straightforward because the socket object carries the authenticated user information from the connection handshake, and the check is localized to the event handler that needs it. An alternative (using per-event middleware via `socket.use()`) would also be valid but less explicit for a single sensitive operation.

## Behaviour changes

**Before fix:** Any authenticated user, regardless of role, can call `admin:broadcastMessage` and broadcast a message to all connected clients.

**After fix:** Only authenticated users with `role === 'admin'` can broadcast. Calls from users with any other role silently return without executing the broadcast. The client receives no acknowledgment or error; the event is simply ignored server-side, which is consistent with returning early on validation failures (as shown in the text-validation check on lines 54–55).

To provide explicit feedback, the handler could emit an error event back to the client (e.g., `socket.emit('error', 'Unauthorized')`) before returning, allowing the client to show the user a message. However, the current pattern of silent rejection is acceptable for this scenario if the UI does not expose the `admin:broadcastMessage` button to non-admin users.
