## Verdict

CONFIRMED

## Source

Line 24 in `adminRoutes.js`: route definition `router.get('/admin/users/export', requireAuth, exportUsersHandler)` missing role authorization middleware.

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

The route for `/admin/users/export` performs a sensitive bulk data export action but was registered with only authentication middleware (`requireAuth`), which verifies the caller has a valid session or JWT. It was missing the authorization check (`requireRole('admin')`) that all sibling admin routes enforce. This allowed any authenticated user—even one without the admin role—to call the endpoint and export all user data, a clear authorization bypass. The fix adds `requireRole('admin')` to the middleware chain, matching the pattern used by comparable admin operations on lines 15-17. The route now rejects requests from authenticated users lacking the admin role with a 403 response before the handler executes, enforcing the intended authorization boundary.

## Behaviour changes

- **Before**: An authenticated user without the admin role could call `GET /admin/users/export` and receive the complete user data export.
- **After**: The `requireRole('admin')` middleware intercepts the request and rejects it with a 403 Forbidden response if the caller lacks the admin role. Only users with the admin role can reach the export handler.
