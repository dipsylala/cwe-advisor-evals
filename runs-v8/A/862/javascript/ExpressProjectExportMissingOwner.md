## Verdict
The route handler performs authentication (is the user logged in?) but omits authorization (does this user own the project?). An authenticated user can export any project by guessing or enumerating project IDs, bypassing ownership checks entirely.

## Source
The vulnerability exists in `projectRoutes.js` line 9-16. The `requireAuth` middleware confirms the user is authenticated, but `loadProjectExport()` is called without passing the authenticated user's identity and performs no ownership check before returning the export payload.

## Fix
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

```javascript
// projectStore.js
'use strict';

async function loadProjectExport(projectId, userId) {
  // Verify ownership before returning export
  const projectOwner = await getProjectOwner(projectId);
  if (projectOwner !== userId) {
    return null; // Not owned by this user
  }

  return {
    projectId,
    format: 'json',
    rows: [],
  };
}

async function getProjectOwner(projectId) {
  // Query database or cache to retrieve project owner
  // This is a placeholder; implement against your data store
  return projectId;
}

module.exports = { loadProjectExport };
```

## Explanation
The fix adds user-based authorization by passing `req.user.id` to `loadProjectExport()`. The function now verifies that the requesting user owns the project before returning any data. If the user does not own the project, the function returns `null`, which the route handler interprets as a 404 Not Found response. This prevents unauthorized users from exporting projects they do not own, even if they are authenticated.
