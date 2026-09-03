## Verdict

Missing authorization check. The route accepts any authenticated user and exports any project without verifying ownership. An attacker can retrieve exports from projects they do not own by modifying the `projectId` parameter.

## Source

Line 9 in projectRoutes.js:

```javascript
router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId);
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }
  res.json(exportPayload);
});
```

The `requireAuth` middleware ensures the user is authenticated, but does not verify that the user owns the requested project. The `loadProjectExport()` function retrieves the export unconditionally.

## Fix

Add an ownership check before returning the export. Reject requests from users who do not own the project:

```javascript
router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId);
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  // Verify the authenticated user owns this project
  if (exportPayload.ownerId !== req.user.id) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }

  res.json(exportPayload);
});
```

The `loadProjectExport()` function must also be modified to return the project's owner ID:

```javascript
async function loadProjectExport(projectId) {
  return {
    projectId,
    ownerId: 'ownerIdFromDatabase', // Fetch from database with the project
    format: 'json',
    rows: [],
  };
}
```

## Explanation

CWE-862 occurs when a resource handler enforces authentication but skips authorization. The route verifies the user is logged in (`requireAuth`) but does not confirm they have permission to access the specific project.

The fix adds an ownership check: after retrieving the project export, compare its `ownerId` against the authenticated user's ID. Return HTTP 403 Forbidden if the user is not the owner, not 404. Returning 404 for authorization failures leaks whether a project exists to unauthorized users.

Ensure the project data structure includes the owner ID and that this value is retrieved from a trusted backend (database) during the `loadProjectExport()` call, not supplied by the client.
