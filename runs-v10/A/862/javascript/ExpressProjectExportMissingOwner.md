## Verdict

**CWE-862: Missing Authorization - CONFIRMED**

The endpoint on line 9 authenticates the user but fails to verify project ownership before exporting. Any authenticated user can export projects belonging to other users.

## Source

**File:** `projectRoutes.js`, **Line:** 9

The route handler `router.get('/projects/:projectId/export', requireAuth, ...)` protects the endpoint with authentication (`requireAuth` middleware) but performs no authorization check. The `loadProjectExport` function returns project data for any `projectId` without verifying the requesting user owns that project.

```javascript
router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId);
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }
  res.json(exportPayload); // No ownership check before returning
});
```

## Fix

Add an ownership check before returning the export. Verify that `req.user` owns the project:

```javascript
router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId);
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  // AUTHORIZATION: Verify the authenticated user owns this project
  if (exportPayload.ownerId !== req.user.id) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }

  res.json(exportPayload);
});
```

Alternatively, if `loadProjectExport` doesn't return owner information, pass both `projectId` and `userId` to a dedicated authorization function:

```javascript
const { canUserAccessProject } = require('./projectAuth');

router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId);
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  // AUTHORIZATION: Verify ownership before returning data
  if (!canUserAccessProject(req.user.id, req.params.projectId)) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }

  res.json(exportPayload);
});
```

## Explanation

CWE-862 occurs when code authenticates a user but fails to verify they have permission for the requested resource. Here, `requireAuth` only checks that a user is logged in—it does not check whether that user owns the project they're exporting.

The fix adds an ownership check between resource retrieval and response. If the authenticated user does not own the project, the handler returns HTTP 403 (Forbidden) instead of the export payload. This enforces the principle that a user can only access resources they own.

The 403 status is preferable to 404 because it correctly indicates the resource exists but is not accessible to this user, rather than implying the resource does not exist (which leaks information about what projects others own).
