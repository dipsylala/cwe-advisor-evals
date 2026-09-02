## Verdict
exploitable

## Source
`req.params.projectId` — attacker-controlled URL parameter passed directly to `loadProjectExport()` without ownership verification.

## Fix

**Vulnerable code:**
```javascript
router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId);  // Missing owner check
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  res.json(exportPayload);
});
```

**Fixed code:**
```javascript
router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId, req.user.id);  // Scoped by owner
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  res.json(exportPayload);
});
```

Additionally, `loadProjectExport()` must scope the lookup to only return projects owned by the provided user:

**Updated `projectStore.js`:**
```javascript
async function loadProjectExport(projectId, ownerId) {
  // Query scoped by both project ID and owner, returning nothing if not owned
  if (ownerId !== getProjectOwner(projectId)) {
    return null;
  }
  return {
    projectId,
    format: 'json',
    rows: [],
  };
}
```

## Explanation

The route applies `requireAuth` middleware which verifies the caller is authenticated, but does not check whether the authenticated user owns the project being exported. An authenticated attacker can modify the `projectId` URL parameter to access another user's project export. The fix adds resource-level authorization by scoping the `loadProjectExport()` lookup to include the authenticated user's ID, so the function returns `null` for projects the caller does not own. The 404 response is returned identically whether the project does not exist or is not owned by the caller, preventing enumeration of other users' resources.

## Behaviour changes

- **Argument added**: `req.user.id` passed to `loadProjectExport()` to scope the lookup by owner.
- **Return value**: `loadProjectExport()` now returns `null` for projects not owned by the authenticated user (previously would have returned them). The route's 404 handling treats "not owned" and "not found" identically.
- **Authorization enforcement**: Requests by authenticated users for projects they do not own now return 403 or 404 (depending on implementation - scoped lookups return 404 indistinguishably) instead of exposing the data.
