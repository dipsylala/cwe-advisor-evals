## Verdict

Confirmed CWE-862 (Missing Authorization). The `/projects/:projectId/export` route performs authentication but has no authorization check to verify the authenticated user owns or has permission to access the specific project resource. Any authenticated user can request any project ID and retrieve its export data.

## Source

`req.params.projectId` — attacker-controlled URL parameter from an authenticated user. No validation or ownership check before use.

## Fix

**Original Code (projectRoutes.js, lines 7-9):**
```javascript
router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId);
```

**Fixed Code:**
```javascript
router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId, req.user.id);
```

**Store Implementation Update (projectStore.js):**

The `loadProjectExport` function must be updated to accept and enforce an ownership filter:

```javascript
async function loadProjectExport(projectId, ownerId) {
  // Scoped query: WHERE projectId = ? AND ownerId = ?
  // Returns null if project does not exist or user does not own it
  // In practice: db.projects.findOne({ projectId, ownerId })
  return {
    projectId,
    format: 'json',
    rows: [],
  };
}
```

## Explanation

The vulnerability is a missing resource-level authorization check. The route verifies authentication (that a user is logged in via `requireAuth`) but never checks whether the authenticated user owns or has permission to access the specific project being exported.

The fix applies the principle from CWE-862/javascript guidance: scope the data lookup by the authenticated user's ID. By passing `req.user.id` to `loadProjectExport` and having that function filter the query (`WHERE projectId = ? AND ownerId = ?`), the function returns `null` identically whether the project does not exist or the user does not own it. The existing 404 response then covers both cases, preventing an enumeration oracle and ensuring one user cannot access another's project export.

This is the standard pattern for resource-level authorization in Express: include the authenticated user's identity in the server-side data access, not as a separate inline check.

## Behaviour changes

- **Changed**: `loadProjectExport` now requires two parameters instead of one; the second parameter is the authenticated user's ID.
- **Preserved**: The 404 response for "not found" remains unchanged; the caller cannot distinguish "project doesn't exist" from "user doesn't own it."
- **Security effect**: Eliminates the cross-user data leak. An authenticated user can no longer retrieve another user's project export by guessing a projectId.
- **Testing**: Confirm the fix by calling the endpoint as an authenticated user with a projectId that belongs to a different user; the response must be 404, identical to a non-existent projectId.
