## Verdict

Confirmed. `GET /projects/:projectId/export` requires an authenticated session (`requireAuth`) but never checks that the authenticated user is allowed to access the specific project named by `:projectId`. Any logged-in user can supply an arbitrary `projectId` and receive that project's export data - a classic authentication-without-authorization (IDOR/BOLA) gap.

## Source

- Tainted input: `req.params.projectId`, the route parameter in `projectRoutes.js`.
- Path: `router.get('/projects/:projectId/export', requireAuth, ...)` -> `requireAuth` only verifies `req.user` is set (`sessionAuth.js`), it never touches `projectId` -> `loadProjectExport(req.params.projectId)` (`projectStore.js`) fetches and returns the project's data keyed solely by the attacker-controlled `projectId`, with no comparison against the requesting user.
- Sink: `res.json(exportPayload)` in `projectRoutes.js`, which sends the project's export to whoever supplied a valid `projectId`, regardless of ownership.

## Fix

### File: projectRoutes.js
```javascript
'use strict';

const express = require('express');
const { requireAuth } = require('./sessionAuth');
const { loadProjectExport } = require('./projectStore');

const router = express.Router();

router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId);
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  if (exportPayload.ownerId !== req.user.id) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }

  res.json(exportPayload);
});

module.exports = router;
```

### File: projectStore.js
```javascript
'use strict';

// Project records, each tracking the user id that owns the project.
const projects = new Map([
  ['project-1', { projectId: 'project-1', ownerId: 'user-1', format: 'json', rows: [] }],
]);

async function loadProjectExport(projectId) {
  const project = projects.get(projectId);
  return project || null;
}

module.exports = { loadProjectExport };
```

## Explanation

`requireAuth` only proves *who* is calling (authentication); it says nothing about *which projects* that caller may access (authorization). The handler used the caller-supplied `projectId` to fetch and return data without ever comparing it against the caller's identity, so authentication alone was mistaken for sufficient access control.

The fix adds the missing authorization check: after the project is loaded, its `ownerId` is compared against `req.user.id`, and the request is rejected with `403 Forbidden` on a mismatch before any project data is serialized. Returning 404 for a non-existent project and 403 for an existing-but-not-owned one avoids leaking which outcome occurred to an unauthorized caller in a way that would help enumerate valid IDs (404 is used for "no such resource," 403 only once the resource is confirmed to exist but is not this user's).

`projectStore.js` is updated to actually carry an `ownerId` per project so the check has real data to compare against; previously it returned the same static payload for any `projectId` with no ownership information at all, which is what made the missing check impossible to enforce correctly. This keeps the fix aligned with a "reject rather than silently coerce" approach: a mismatched owner is denied outright rather than papered over or filtered after the fact.
