## Verdict

exploitable (confidence: high)

- cwe_id: CWE-862 (Missing Authorization)
- location: chatServer.js, line 52 (`socket.on('admin:broadcastMessage', ...)`), sink at line 57 (`io.emit('chat:announcement', ...)`)

## Source

The `admin:broadcastMessage` event payload, emitted by any socket that has completed the `io.use()` handshake middleware (lines 15-31). That middleware only verifies the JWT is valid and attaches `socket.user = { id, username, role }` to the connection - it establishes authentication, not authorization, and it runs once per connection, not once per event. Any authenticated user, regardless of `socket.user.role`, can emit `admin:broadcastMessage` on their existing connection.

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

    // io.use() only authenticates the connection; it does not authorize
    // individual events. This is an admin-only action, so the handler
    // checks the caller's role itself before broadcasting.
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

`io.use()` authenticates the socket once at connect time and never runs again for later events on that same connection, so it cannot serve as authorization for a specific event. The `admin:broadcastMessage` handler is an admin-only action but previously ran for any authenticated caller. The fix adds an in-handler check of `socket.user.role`, populated at connection time straight from the verified JWT's `role` claim (not from anything client-supplied on the event payload), and returns immediately without broadcasting if the caller is not `admin`. This mirrors how `chat:sendMessage` already trusts `socket.user` for its `from` field, so no new source of identity is introduced. A dedicated `socket.use()` per-event middleware was considered (per the language guidance) but is unnecessary here since exactly one event needs the extra check; an in-handler check is the smaller, equally correct change for this shape of gap.

## Behaviour changes

- Non-admin authenticated users who previously could trigger a server-wide `chat:announcement` broadcast now have that call silently no-op (matching the existing silent-return style used for invalid payloads on both handlers in this file, e.g. line 39 and line 55) - this is the intended effect of closing the missing-authorization gap, not a side effect.
- No change to admin users' behavior, to `chat:sendMessage`, to `disconnect`, or to any return value, argument, or discarded output of `io.emit`/`io.to().emit`.
- No new dependencies, exports, or public API changes.

Verification: `node --check` run against the fixed file in a scratch copy outside the repository - passed with no syntax errors. No project test suite was available in the case directory to exercise role-based behavior, so no automated behavioral test was run; the `role !== 'admin'` check was read against the trace confirming `socket.user.role` is set exclusively from the server-verified JWT payload at connection time (line 25), not from any client-controlled event payload.
