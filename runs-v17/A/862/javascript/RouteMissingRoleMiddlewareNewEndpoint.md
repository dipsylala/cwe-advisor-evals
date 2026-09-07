## Verdict

CONFIRMED. The `/admin/users/export` endpoint on line 24 is missing the `requireRole('admin')` authorization middleware that all other admin routes consistently apply. Any authenticated user can access this sensitive endpoint, bypassing role-based access control.

## Source

**File**: adminRoutes.js  
**Line**: 24  
**Current code**:
```javascript
router.get('/admin/users/export', requireAuth, exportUsersHandler);
```

The route chains only `requireAuth` (verifies login) before reaching `exportUsersHandler`, but omits the `requireRole('admin')` check that appears on every sibling admin route (lines 15–17).

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

The export endpoint grants access to bulk user data—equivalent in sensitivity to user deletion or bans. While `requireAuth` ensures the caller is logged in, authorization (role verification) is missing.

The fix inserts `requireRole('admin')` into the middleware chain immediately after `requireAuth`, matching the pattern established by all sibling admin routes. This ensures only users holding the `admin` role can reach `exportUsersHandler`, closing the CWE-862 authorization gap.

The change is minimal, surgical, and brings the newer endpoint into conformance with the role-based access control strategy already in place for the older admin operations.
