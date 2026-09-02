## Verdict

Confirmed. `GET /projects/:projectId/export` in `projectRoutes.js` only checks that a session exists (`requireAuth`); it never checks that the authenticated user owns (or otherwise has access to) the project identified by `req.params.projectId`. Any logged-in user can supply an arbitrary `projectId` and receive that project's export data.

## Source

- Tainted input: `req.params.projectId` (attacker-controlled URL path segment) in `projectRoutes.js:10`.
- Identity input: `req.user` (the authenticated session's user, established by `requireAuth`).
- Sink: `loadProjectExport(req.params.projectId)` in `projectRoutes.js:10`, which fetches and returns the full project export with no relationship check between `req.user` and the project, and the result is sent directly to the client via `res.json(exportPayload)`.

`requireAuth` (`sessionAuth.js`) only verifies `req.user` is present - it is authentication, not authorization. There is no code anywhere in the call chain that compares the requesting user to the project's owner before the data is loaded and returned. This is a textbook missing-authorization / IDOR (Insecure Direct Object Reference) flaw.

## Fix

Add an ownership check between authentication and the response, so the lookup itself is scoped to the requesting user rather than trusting the path parameter alone.

`projectStore.js`:

```javascript
'use strict';

// Example: replace with the real persistence lookup for project ownership.
async function getProjectOwnerId(projectId) {
  const project = await db.projects.findById(projectId);
  return project ? project.ownerId : null;
}

async function loadProjectExport(projectId, requestingUserId) {
  const ownerId = await getProjectOwnerId(projectId);

  if (ownerId === null) {
    return null; // project does not exist
  }

  if (ownerId !== requestingUserId) {
    return null; // exists, but caller does not own it
  }

  return {
    projectId,
    format: 'json',
    rows: [], // populated from the real data source
  };
}

module.exports = { loadProjectExport };
```

`projectRoutes.js`:

```javascript
'use strict';

const express = require('express');
const { requireAuth } = require('./sessionAuth');
const { loadProjectExport } = require('./projectStore');

const router = express.Router();

router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const exportPayload = await loadProjectExport(req.params.projectId, req.user.id);
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  res.json(exportPayload);
});

module.exports = router;
```

The route passes `req.user.id` into the store so the ownership check happens where the project's owner is actually known, rather than trying to compare against an object the route doesn't have. Both "project does not exist" and "project exists but belongs to someone else" collapse to the same 404, so the endpoint doesn't leak project IDs to unauthorized users by responding differently for the two cases.

## Explanation

`requireAuth` establishes *who is calling* but says nothing about *what that caller is allowed to touch*. Authentication and authorization are separate controls, and an endpoint that takes a resource ID straight from the URL and hands it to a data-loading function - with no comparison against the caller's identity - is missing the second control entirely. Any authenticated account, regardless of relationship to the project, could enumerate `projectId` values and exfiltrate every project's export data.

The fix moves the ownership check into the data-access path (`loadProjectExport`) rather than bolting it onto the route as a second, separable step, so future callers of `loadProjectExport` can't accidentally reintroduce the bug by forgetting a manual check before calling it. Returning `null` uniformly for "not found" and "not owned" also avoids turning the endpoint into an oracle that confirms which project IDs exist to users who have no access to them.
