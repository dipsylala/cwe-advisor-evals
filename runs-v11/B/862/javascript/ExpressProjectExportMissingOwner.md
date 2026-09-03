## Verdict

Exploitable. An authenticated user can export any project by supplying its ID in the URL, regardless of ownership. The `requireAuth` middleware verifies authentication (is the user logged in?) but the handler contains no authorization check (does this user own the project?). An attacker with a valid session can enumerate project IDs and retrieve confidential export data belonging to other users.

## Source

`req.params.projectId` from the GET request path `/projects/:projectId/export` at line 9.

## Fix

**Vulnerable Code:**
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

**Fixed Code (Option A - In-handler ownership check):**
```javascript
router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId);
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  // Authorization: verify the authenticated user owns this project
  if (exportPayload.ownerId !== req.user.id) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  res.json(exportPayload);
});
```

**Fixed Code (Option B - Database scoping, preferred):**

Modify `loadProjectExport` to accept the authenticated user's ID and scope the lookup:

```javascript
// In projectRoutes.js
router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId, req.user.id);
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  res.json(exportPayload);
});

// In projectStore.js
async function loadProjectExport(projectId, userId) {
  // Query database: SELECT * FROM projects WHERE id = ? AND ownerId = ?
  // This ensures the record cannot be loaded unless it belongs to the user
  const data = await db.query('SELECT * FROM projects WHERE id = ? AND ownerId = ?', [projectId, userId]);
  return data.length > 0 ? data[0] : null;
}
```

## Explanation

The vulnerability exists because authentication (verifying `req.user` exists) and authorization (verifying the user owns the resource) are separate concerns, and only the former is implemented. The `requireAuth` middleware confirms a valid session exists, but the handler proceeds directly to `loadProjectExport` without checking whether `req.user.id` matches the project's owner.

Option A (in-handler check) adds the missing authorization step: if the export payload's `ownerId` does not match the authenticated user's ID, the handler returns 404 identically to the "not found" case. This prevents information disclosure (distinguishing "not yours" from "doesn't exist") and matches the codebase's current error handling.

Option B (database scoping) is the preferred approach per CWE-862 guidance: the database query itself filters by `ownerId`, ensuring the record cannot be loaded at all unless it belongs to the user. This is more robust because it eliminates the vulnerability at the data-access layer rather than relying on a conditional check in application code. The function now acts as both authentication and authorization by construction - a malicious or buggy caller cannot accidentally return the wrong user's data.

Both options return 404 (not found) rather than 403 (forbidden) when the check fails, which is intentional: a 403 would reveal the project exists, turning the ID space into an enumeration oracle for a guessing attacker. Returning 404 identically for "not yours" and "doesn't exist" closes that leak.

## Behaviour changes

**Option A:**
- Adds an additional conditional check before the response payload is returned. The function still loads the project by ID alone (unchanged sink contract), but adds a guard that discards the response if ownership does not match.
- The response is identical in both "not yours" and "not found" cases (404), so the caller cannot distinguish them. This is intentional and required by CWE-862 guidance to prevent enumeration.

**Option B:**
- Changes the signature of `loadProjectExport(projectId)` to `loadProjectExport(projectId, userId)`, so every caller must be updated.
- The database query now filters by both `projectId` and `ownerId`, so the function returns `null` if either condition fails. This changes the sink contract - the query itself now enforces authorization rather than the caller doing so.
- Returns 404 identically for "not yours" and "doesn't exist" (same as Option A, by virtue of the scoped query), which prevents enumeration.
- More robust long-term: a future developer adding a new call to `loadProjectExport(id, userId)` automatically benefits from the ownership check without remembering to add it manually.
