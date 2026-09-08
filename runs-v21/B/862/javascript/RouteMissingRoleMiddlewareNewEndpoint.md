## Verdict

Exploitable. The route `/admin/users/export` at line 24 performs a sensitive administrative action (exporting all user data) but applies only authentication middleware (`requireAuth`) without the role-based authorization check (`requireRole('admin')`) that all sibling administrative routes require. An authenticated non-admin user can reach the handler and call `exportUsersHandler`, exporting sensitive data they should not access.

## Source

An authenticated attacker with a valid session or JWT but without the admin role can make a GET request to `/admin/users/export`. The `requireAuth` middleware verifies the session is valid, but there is no subsequent role check to verify the caller holds the admin role.

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
// FIXED: Added requireRole('admin') middleware to match sibling routes.
router.get('/admin/users/export', requireAuth, requireRole('admin'), exportUsersHandler);

module.exports = router;
```

## Explanation

The fix adds the missing `requireRole('admin')` middleware to the `/admin/users/export` route, applying the same authorization pattern established by all other administrative routes in the file. The route now enforces both authentication (the caller is logged in) and authorization (the caller holds the admin role) before reaching the handler. This follows the CWE-862 remediation principle of applying authorization through centralized middleware consistent with comparable routes, rather than an inline check within the handler. The fix closes the authorization gap without changing any other behavior or the route's existing contract with the authentication middleware.

## Behaviour changes

None. The fix adds the authorization middleware that was already present on all sibling routes, maintaining the existing middleware chain contract. The route still receives an authenticated user through `requireAuth`, and now also enforces the admin role requirement through `requireRole('admin')` before the handler executes, matching the implementation pattern of the other administrative endpoints in the file.
