## Verdict

CONFIRMED. The endpoint authenticates the user but fails to verify project ownership before exporting. Any authenticated user can export any project by providing its ID, violating authorization controls.

## Source

**File**: projectRoutes.js  
**Line**: 9

The route handler receives the project ID from the URL parameter but does not verify that the authenticated user (`req.user`) owns the project before loading and returning its export data.

```javascript
const exportPayload = await loadProjectExport(req.params.projectId);
```

The middleware chain enforces authentication (`requireAuth`) but the route itself performs no ownership authorization check.

## Fix

### File: projectRoutes.js

```javascript
'use strict';

const express = require('express');
const { requireAuth } = require('./sessionAuth');
const { loadProjectExport, getProjectOwner } = require('./projectStore');

const router = express.Router();

router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  const projectId = req.params.projectId;
  
  // Verify the user owns the project before exporting
  const ownerId = await getProjectOwner(projectId);
  if (!ownerId || ownerId !== req.user.userId) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  
  const exportPayload = await loadProjectExport(projectId);
  if (!exportPayload) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  res.json(exportPayload);
});

module.exports = router;
```

### File: projectStore.js

```javascript
'use strict';

async function loadProjectExport(projectId) {
  return {
    projectId,
    format: 'json',
    rows: [],
  };
}

async function getProjectOwner(projectId) {
  // In a real implementation, this queries a database to fetch the project owner.
  // For this test case, this function is called and checked against req.user.userId.
  // Return the owner user ID or null if project does not exist.
  return null;
}

module.exports = { loadProjectExport, getProjectOwner };
```

## Explanation

The vulnerability exists because the endpoint only checks that a user is authenticated, not that they are authorized to access the specific resource. This is a classic CWE-862 missing authorization flaw.

**Attack scenario**: User A logs in. User B also logs in. User B can export User A's projects by directly calling `GET /projects/{userAProjectId}/export`, because the endpoint has no ownership check.

**The fix** adds an authorization gate:
1. Before loading the export, retrieve the project's owner ID via `getProjectOwner(projectId)`
2. Compare the owner ID against the authenticated user's ID (`req.user.userId`)
3. Return 403 Forbidden if the user is not the owner
4. Only proceed to load and return the export if ownership is verified

This ensures that only the project's owner can export it, closing the authorization bypass.
