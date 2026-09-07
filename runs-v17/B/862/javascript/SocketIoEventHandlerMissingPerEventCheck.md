## Verdict

**VULNERABLE.** The `admin:broadcastMessage` event handler (line 52) performs a server-wide broadcast without checking whether the authenticated user has the `admin` role. The authentication middleware verifies only that the user holds a valid JWT token; it does not authorize specific actions. Any authenticated user can emit this event and broadcast a message to all connected clients.

## Source

The vulnerability is in the `admin:broadcastMessage` event handler at line 52 of `chatServer.js`. The handler reads a text payload and calls `io.emit('chat:announcement', ...)` to broadcast to all connected users, but does not check `socket.user.role`.

The authentication middleware (lines 15–31) runs once when the socket connects and verifies the JWT token is valid, storing the decoded user (including role) on `socket.user`. The middleware does not run again for each event. Socket.IO's `io.use()` runs per connection, not per event, so the role check must happen inside the event handler itself.

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

    // Authorization check added: only admin role can broadcast
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

The fix adds an explicit role check at the start of the `admin:broadcastMessage` event handler. If `socket.user.role` is not `'admin'`, the handler returns early without broadcasting. This ensures that only authenticated users with the `admin` role can emit server-wide announcements.

The check is placed in the event handler because Socket.IO's `io.use()` middleware runs once per connection, not per event. To authorize actions on a per-event basis, the check must live inside the event handler. The role value comes from the JWT token, which was verified during the initial authentication handshake and is not attacker-controlled.

## Behaviour changes

- **Authenticated users without `admin` role**: Attempting to emit `admin:broadcastMessage` now results in the event being silently ignored (returns early without broadcasting).
- **Admin users**: No change; their broadcasts continue to work as before.
- **Non-authenticated users**: Already rejected by the connection middleware, unchanged.

The silent return maintains backward compatibility with clients that may attempt this action without expecting an error response.
