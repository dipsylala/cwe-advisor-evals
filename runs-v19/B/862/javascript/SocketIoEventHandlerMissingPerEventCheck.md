## Verdict

CONFIRMED. The `admin:broadcastMessage` event handler at line 52 performs an admin-only action (server-wide broadcast via `io.emit()`) without verifying the caller's role. The connection-time authentication middleware (`io.use()` at line 15) verifies only that the caller holds a valid JWT token, not that they hold the admin role. Socket.IO middleware registered with `io.use()` runs once per connection and not again per event, so per-event authorization must be added as an in-handler check or via `socket.use()` middleware.

## Source

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

An authenticated user with any role (not just admin) can invoke this event and trigger a server-wide broadcast.

## Fix

### File: chatServer.js

```javascript
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;

function createChatServer(httpServer) {
  const io = new Server(httpServer, {
    cors: { origin: process.env.CLIENT_ORIGIN },
  });

  // Runs once when the socket first connects. It confirms the caller holds a
  // valid session token and attaches the decoded user to the socket, but it
  // does not run again for each event the client later emits on this
  // connection.
  io.use((socket, next) => {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    if (!token) {
      return next(new Error('authentication required'));
    }
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.user = {
        id: decoded.sub,
        username: decoded.username,
        role: decoded.role,
      };
      next();
    } catch (err) {
      next(new Error('invalid token'));
    }
  });

  io.on('connection', (socket) => {
    socket.join(`user:${socket.user.id}`);

    socket.on('chat:sendMessage', (payload) => {
      const { roomId, text } = payload || {};
      if (!roomId || typeof text !== 'string' || !text.trim()) {
        return;
      }
      io.to(roomId).emit('chat:message', {
        from: socket.user.username,
        text: text.slice(0, 2000),
        sentAt: Date.now(),
      });
    });

    // Authorization check added: verify caller holds admin role before
    // performing this admin-only action.
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

    socket.on('disconnect', () => {
      socket.leave(`user:${socket.user.id}`);
    });
  });

  return io;
}

module.exports = { createChatServer };
```

## Explanation

The fix adds an explicit authorization check at the start of the `admin:broadcastMessage` event handler that verifies `socket.user.role === 'admin'` before allowing the broadcast. If the role is not admin, the handler returns early without performing the action, matching the existing validation pattern used for payload checks.

Socket.IO's `io.use()` middleware runs once per connection and verifies only authentication (token validity), not authorization (role or permission). Since each event handler executes independently after that single connection-time check, per-event authorization requires an explicit in-handler check or a per-event middleware via `socket.use()`. The in-handler approach is simpler here and consistent with the existing code's validation patterns.

The fix preserves all existing behavior for authenticated admin users and the role value propagated from the JWT token. Non-admin authenticated users are silently denied, consistent with how invalid payloads are handled elsewhere in the handler.

## Behaviour changes

- Authenticated users with `role !== 'admin'` can no longer invoke the `admin:broadcastMessage` event; the handler returns without broadcasting.
- Authenticated users with `role === 'admin'` retain unchanged behavior.
- No changes to response codes or error messaging (the handler silently returns on authorization failure, matching the existing pattern for payload validation).
