## Verdict

Exploitable. An authenticated non-admin user can trigger the `/admin/users/export` endpoint and receive sensitive data (all users' profiles, emails, and billing history) because the route has only authentication middleware (`requireAuth`) but is missing the authorization check (`requireRole('admin')`) that all sibling sensitive admin routes enforce.

## Source

Request flow: An authenticated caller makes a GET request to `/admin/users/export` without holding the admin role. The request passes through `requireAuth` middleware, which validates only that `req.session.userId` exists. No authorization check occurs before the handler executes.

## Fix

### File: adminRoutes.js

```javascript
const express = require('express');
const { requireAuth, requireRole } = require('./authMiddleware');
const {
  banUserHandler,
  unbanUserHandler,
  deleteUserHandler,
  exportUsersHandler,
} = require('./adminHandlers');

const router = express.Router();

// Existing admin routes: every one of these chains requireAuth (must be
// logged in) with requireRole('admin') (must hold the admin role) before
// the handler runs.
router.post('/admin/users/:id/ban', requireAuth, requireRole('admin'), banUserHandler);
router.post('/admin/users/:id/unban', requireAuth, requireRole('admin'), unbanUserHandler);
router.delete('/admin/users/:id', requireAuth, requireRole('admin'), deleteUserHandler);

// Newer route added for the bulk data-export feature. It reuses requireAuth
// so only logged-in callers reach the handler, but the admin role check
// that every sibling route above applies was left off even though a full
// user data export is at least as sensitive as a ban or delete.
// FIXED: Added requireRole('admin') middleware.
router.get('/admin/users/export', requireAuth, requireRole('admin'), exportUsersHandler);

module.exports = router;
```

## Explanation

The fix adds `requireRole('admin')` middleware to the `/admin/users/export` route, between authentication and the handler. This matches the middleware chain used by all sibling sensitive admin routes (ban, unban, delete). The middleware checks whether the authenticated caller's `req.session.role` equals `'admin'` and returns 403 Forbidden if not, preventing non-admin authenticated users from reaching `exportUsersHandler`. Authentication (verifying the caller is logged in) and authorization (verifying the caller holds the admin role) are now both required, closing the missing authorization gap. The fix uses the same centralized mechanism that the application already applies to comparable sensitive operations, rather than an inline check.

## Behaviour changes

None beyond closing the authorization gap. For authorized (admin) callers, the route's behavior, return value, and response are identical. For unauthorized (authenticated non-admin) callers, the response changes from 200 with sensitive data to 403 Forbidden, which is the correct security boundary.
