## Verdict

Confirmed. `admin:broadcastMessage` is an admin-only action (a server-wide broadcast) but the handler performs no authorization check of its own. The Socket.IO `io.use()` middleware only verifies that the connection belongs to an authenticated user; it runs once at connection time and establishes authentication, not per-event authorization. Any authenticated socket, regardless of role, can emit `admin:broadcastMessage` and have its text broadcast to every connected client via `io.emit`.

## Source

`socket.handshake.auth.token`, decoded by `jwt.verify` in the connection middleware (line 21) into `socket.user` (including `socket.user.role`), and the payload passed by the client to the `admin:broadcastMessage` event (line 52-53). The role is available on the socket but is never read before the privileged action executes.

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

    // Authentication (io.use() above) only proves who the caller is; it does
    // not run again per event, so each privileged event must check the
    // caller's role for itself. This is an admin-only action, so it is
    // rejected unless socket.user.role is 'admin'.
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

Socket.IO connection middleware (`io.use`) runs exactly once, when the handshake completes, before any `connection` listener fires. It does not re-run for each event a client later emits over that same socket, so it can only establish who the caller is (authentication) - it cannot enforce which actions that caller is allowed to perform (authorization). Each event handler that performs a privileged action must therefore check the caller's authorization for itself, using the identity/role data the middleware already attached to the socket.

The fix adds an explicit role check (`socket.user.role !== 'admin'`) as the first statement in the `admin:broadcastMessage` handler, before any payload validation or the privileged `io.emit` broadcast, and returns early - mirroring the existing early-return style used for input validation elsewhere in the file - for any non-admin caller. This is a minimal, targeted per-event authorization check: it does not change the shape of the middleware, the event contract, or any other handler, and it uses data (`socket.user.role`) that the connection middleware already decodes from the verified JWT, so no new source of trust is introduced.
