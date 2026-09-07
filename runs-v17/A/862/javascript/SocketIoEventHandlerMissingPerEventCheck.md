## Verdict

CONFIRMED. The `admin:broadcastMessage` event handler at line 52 lacks authorization checking. While the connection-level authentication middleware verifies the JWT token, it does not execute per-event. An authenticated user with any role can broadcast messages to the entire server, bypassing the admin-only access control that should guard this operation.

## Source

**File:** chatServer.js  
**Line:** 52  
**Issue:** The event handler `socket.on('admin:broadcastMessage', ...)` performs a privileged broadcast operation (`io.emit()`) without checking the user's role, despite the role being decoded and available in `socket.user.role`.

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

The vulnerability occurs because Socket.IO's connection-level `io.use()` middleware runs once during the handshake and does not re-execute for each event. The `admin:broadcastMessage` handler is a privileged operation that should only be callable by users with the `admin` role, but it was missing the per-event authorization check.

The fix adds a role check at the start of the handler (line 52–54 in the fixed version): if `socket.user.role` is not `'admin'`, the handler returns early without executing the broadcast. This ensures that only authenticated users with the admin role can trigger server-wide announcements, while other authenticated users can only access the standard `chat:sendMessage` functionality.

The role value is already securely decoded from the JWT token during connection and stored in `socket.user.role`, so the check reuses that already-authenticated context.
