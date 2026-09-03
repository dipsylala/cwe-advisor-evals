## Verdict

exploitable

## Source

File: evals/cases/862/javascript/RouteMissingRoleMiddlewareNewEndpoint/adminRoutes.js
Line: 24

Data flow: The route handler `exportUsersHandler` at line 24 processes a request to `/admin/users/export` after only authentication middleware (`requireAuth`), with no authorization check for the admin role. An authenticated user without admin privileges can invoke this endpoint and trigger a bulk export of all user data, a sensitive action that other admin routes (ban, unban, delete) guard with `requireRole('admin')`.

## Fix

**Vulnerable code:**
```javascript
router.get('/admin/users/export', requireAuth, exportUsersHandler);
```

**Fixed code:**
```javascript
router.get('/admin/users/export', requireAuth, requireRole('admin'), exportUsersHandler);
```

## Explanation

The `/admin/users/export` route was added to the router without the `requireRole('admin')` authorization middleware that every sibling admin route applies. This allows any authenticated user, regardless of role, to reach the handler and trigger a full user data export. The fix adds the missing middleware to the route definition, bringing it into alignment with comparable routes (ban, unban, delete) and ensuring only users holding the admin role can execute the export. The middleware runs before the handler and returns a 403 Forbidden response to any user lacking the required role.

## Behaviour changes

none

All authorized admin users experience identical behaviour; the handler signature, return value, and data flow remain unchanged. Only the authorization gate is added. Unauthorized users receive a 403 Forbidden from the middleware instead of reaching the handler, which is the correct security behaviour and matches the pattern established by other admin routes in the same file.
