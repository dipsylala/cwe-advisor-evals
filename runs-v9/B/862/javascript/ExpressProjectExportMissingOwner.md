## Verdict

exploitable (confidence: high)

## Source

`req.params.projectId` (URL path parameter, attacker-controlled) combined with `req.user` established by `requireAuth` in `sessionAuth.js` (confirms only that a session exists, carries no ownership or role check) - `projectRoutes.js` line 9, `GET /projects/:projectId/export`.

## Fix

Vulnerable code (`projectRoutes.js`):

```javascript
router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId); // no ownership check - any authenticated user can export any project
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  res.json(exportPayload);
});
```

Fixed code (`projectRoutes.js`):

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

Fixed code (`projectStore.js`):

```javascript
async function loadProjectExport(projectId, ownerId) {
  const project = await Project.findOne({ _id: projectId, ownerId });
  if (!project) {
    return null;
  }

  return {
    projectId,
    format: 'json',
    rows: project.rows,
  };
}
```

## Explanation

`requireAuth` only checks `req.user` is set (authentication), and the handler passed `req.params.projectId` straight to `loadProjectExport` with no ownership check, so any authenticated user could export any other user's project by changing the `projectId` in the URL - a missing object-level authorization check (CWE-862). The fix scopes the lookup by the authenticated caller (`req.user.id`) alongside the requested `projectId`, following the same pattern as sibling routes in this codebase's guidance (`findOne({ _id: id, ownerId: req.user.id })`), and returns `null` when no matching record exists for that caller. `projectRoutes.js` then answers `404` for that `null` result, which is the same status code it already used for a genuinely unknown `projectId` - so "not yours" and "does not exist" remain indistinguishable to the caller, avoiding turning the endpoint into an existence-enumeration oracle.

## Behaviour changes

- Added a second argument (`req.user.id`) to the `loadProjectExport` call in `projectRoutes.js` - required to carry the caller's identity into the scoped lookup; the original call had no way to enforce ownership.
- Changed `loadProjectExport`'s signature to accept `ownerId` and scope the record lookup by both `projectId` and `ownerId`, returning `null` when the pair doesn't match - closes the missing authorization check. The concrete lookup call (`Project.findOne(...)`) is illustrative of the scoped-query pattern this codebase's other routes should already use; the persistence layer backing `loadProjectExport` was not part of the provided call chain (the fixture's original implementation was an unconditional stub with no datastore), so the actual query API should be matched to whatever ORM/store the rest of the codebase uses.
- No change to `requireAuth`/`sessionAuth.js` - it already performs authentication correctly and is not the source of the gap.
- Response codes are unchanged: `404` for both "project not found" and "project not owned by caller," `200` with the export payload otherwise - a caller who owns the project sees no behavior change.
