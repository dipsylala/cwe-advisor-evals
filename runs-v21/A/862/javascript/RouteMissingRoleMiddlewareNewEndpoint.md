## Verdict
The vulnerability is confirmed. The route handler for `/admin/users/export` on line 24 chains only `requireAuth` middleware but omits the `requireRole('admin')` check that every sibling administrative route enforces. An authenticated non-admin user can export the full user dataset.

## Source
Line 24 in `adminRoutes.js` defines an unauthenticated administrative endpoint:
```javascript
router.get('/admin/users/export', requireAuth, exportUsersHandler);
```

The route should chain the same role-based access control as lines 15–17, which each apply both `requireAuth` and `requireRole('admin')` before invoking their handlers.

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
// SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
router.get('/admin/users/export', requireAuth, requireRole('admin'), exportUsersHandler);

module.exports = router;
```

## Explanation
The fix adds `requireRole('admin')` to the middleware chain for the `/admin/users/export` route. This enforces role-based authorization alongside authentication, matching the defence pattern established by the ban, unban, and delete routes.

Bulk user data export is a sensitive administrative operation. The missing role check allowed any authenticated user—not just admins—to access it. Now the endpoint verifies both that the caller is logged in and that they hold the admin role before the handler executes.
