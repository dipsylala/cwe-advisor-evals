## Verdict

Exploitable.

## Source

`req.params.projectId` (untrusted URL parameter supplied by the attacker).

## Fix

**File: projectRoutes.js (line 9)**

Vulnerable code:
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

Fixed code:
```javascript
router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId, req.user.id);
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  res.json(exportPayload);
});
```

**File: projectStore.js (line 3)**

Vulnerable code:
```javascript
async function loadProjectExport(projectId) {
  return {
    projectId,
    format: 'json',
    rows: [],
  };
}
```

Fixed code:
```javascript
async function loadProjectExport(projectId, userId) {
  // Scope the query to projects owned by the authenticated user
  // Example with database: const project = await db.projects.findOne({ _id: projectId, ownerId: userId });
  // Return 404 identically for "not found" and "not yours" to prevent enumeration
  
  // Mock implementation showing the ownership check pattern:
  // In production, this would query: WHERE id = projectId AND owner_id = userId
  const project = await db.query(
    'SELECT * FROM projects WHERE id = ? AND owner_id = ?',
    [projectId, userId]
  );
  
  if (!project) {
    return null;  // 404 returned by route handler for both "not found" and "not yours"
  }

  return {
    projectId: project.id,
    format: 'json',
    rows: project.data,
  };
}
```

## Explanation

The route has authentication middleware (`requireAuth`) but no authorization check. An authenticated user could access another user's project export by changing the `projectId` parameter. The fix adds a `userId` parameter to `loadProjectExport` and scopes the query by both the `projectId` and the authenticated user's `ownerId`. This ensures the function returns `null` for projects not owned by the caller, which the route handler treats identically to a non-existent project (404). Both "not yours" and "not found" return the same status and body, preventing an attacker from using the response to enumerate valid project IDs. The authentication middleware (`requireAuth`) remains as the first check; the authorization check (ownership) runs immediately after via the scoped database query.

## Behaviour changes

- `loadProjectExport` now requires a second parameter `userId` to scope the lookup by owner
- The function returns `null` for both missing projects and projects not owned by the user, instead of returning any project by ID
- The route handler passes `req.user.id` to the function so the ownership check can run server-side
