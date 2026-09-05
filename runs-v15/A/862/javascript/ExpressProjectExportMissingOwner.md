## Verdict

The endpoint at line 9 of `projectRoutes.js` is missing authorization. While the route requires authentication via `requireAuth`, it does not verify that the authenticated user owns the project they are requesting to export. An authenticated user can export any project in the system by changing the `projectId` URL parameter.

## Source

The vulnerability exists in the route handler at line 9:

```javascript
const exportPayload = await loadProjectExport(req.params.projectId);
```

The route accepts any `projectId` from the URL without checking ownership. The `requireAuth` middleware only verifies that a user is authenticated, not that they have permission to access the specific project.

## Fix

Add an ownership check before loading the project export:

```javascript
router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  // Verify the authenticated user owns this project
  if (!await userOwnsProject(req.user.id, req.params.projectId)) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }

  const exportPayload = await loadProjectExport(req.params.projectId);
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  res.json(exportPayload);
});
```

The fix adds a check `userOwnsProject()` that verifies the authenticated user (`req.user.id`) is the owner of the requested project before proceeding with the export. A 403 Forbidden response is returned if the user lacks ownership.

## Explanation

CWE-862 (Missing Authorization) occurs when a system enforces authentication but not authorization—verifying who a user is without checking what they are allowed to do. In this case, `requireAuth` ensures a user is logged in, but the endpoint grants access to any project without verifying ownership.

The fix is a resource-level authorization check that bridges the gap between authentication and authorization. Before any sensitive operation (like exporting a project), verify that the authenticated user is authorized to perform that operation on the specific resource. This typically involves checking a relationship between the user and the resource (ownership, group membership, or role-based access). A 403 Forbidden response clearly communicates that the user is authenticated but lacks permission, distinguishing it from a 401 Unauthorized response that indicates a missing or invalid session.
