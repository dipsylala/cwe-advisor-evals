## Verdict

Exploitable

## Source

The vulnerability exists in the Socket.IO event handler `admin:broadcastMessage` at line 52. The client-controlled event triggers an operation that broadcasts a message to all connected users without verifying the caller's authorization level.

Socket.IO's `io.use()` authentication middleware (lines 15-31) runs only once at connection time and verifies the JWT token, attaching `socket.user` with role information. However, this middleware does NOT re-run for each event the client emits. As a result, the `admin:broadcastMessage` handler has no per-event authorization check.

**Sink**: `io.emit('chat:announcement', ...)` at line 57 — broadcasts to all connected clients.

**Data Flow**: Any authenticated user can emit the `admin:broadcastMessage` event → handler executes without checking `socket.user.role` → broadcast is sent to all users.

The `admin:broadcastMessage` event handler (lines 52-62) lacks a per-event authorization check for the admin role, even though `socket.user.role` is available from the connection-time authentication middleware.

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

    // The developer assumed io.use() above already covers every event on
    // this connection, so broadcasting a message to the whole server - an
    // admin-only action - has no role check of its own here.
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    socket.on('admin:broadcastMessage', (payload) => {
      // Authorization check: only admins can broadcast
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

The fix adds an explicit per-event authorization check that verifies `socket.user.role === 'admin'` before executing the broadcast operation. This closes the missing authorization vulnerability by ensuring only users with the admin role can trigger the `admin:broadcastMessage` event and reach the `io.emit()` sink. The check fails safely by returning early if the role requirement is not met, preventing non-admin users from broadcasting messages to all connected clients. The authorization check is placed inside the event handler (rather than as centralized middleware) because only this specific event has the admin-only requirement; other events like `chat:sendMessage` have different authorization rules or are open to all authenticated users.

## Behaviour changes

- Added a per-event role authorization check immediately after the event handler is invoked
- Non-admin authenticated users will receive no response when emitting `admin:broadcastMessage` and the broadcast will not execute
- The handler returns early (silently) if the user lacks the admin role, consistent with how it already handles invalid text input via early return
- No change to the broadcast message format, `io.emit()` call signature, or behavior for authorized (admin) users
- Verification: Node.js syntax check passed with `node --check` on the fixed file
