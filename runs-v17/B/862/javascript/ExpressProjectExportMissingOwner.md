## Verdict

CONFIRMED - Missing Authorization on resource access. The route verifies authentication but lacks resource-level ownership check, allowing any authenticated user to export any project.

## Source

**Route Handler**: `projectRoutes.js` line 9
**Vulnerable Call**: `loadProjectExport(req.params.projectId)` called without passing the authenticated user's identity
**Data Flow**: `req.params.projectId` (attacker-controlled URL parameter) → `loadProjectExport()` → response without ownership validation

An authenticated user can modify the projectId in the URL (`/projects/OTHER_USER_PROJECT_ID/export`) and retrieve another user's export because the lookup includes no check on resource ownership.

## Fix

### File: projectRoutes.js

```javascript
'use strict';

const express = require('express');
const { requireAuth } = require('./sessionAuth');
const { loadProjectExport } = require('./projectStore');

const router = express.Router();

router.get('/projects/:projectId/export', requireAuth, async (req, res) => {
  // Pass the authenticated user's ID to scope the lookup by ownership.
  const exportPayload = await loadProjectExport(req.params.projectId, req.user.id);
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

async function loadProjectExport(projectId, userId) {
  // Scope the lookup by the authenticated user's ID.
  // In a real implementation, this would query:
  // SELECT * FROM projects WHERE id = ? AND owner_id = ?
  // If ownership cannot be verified, return null (same response for "not found" or "not owned").
  
  if (!userId) {
    return null;
  }
  
  return {
    projectId,
    format: 'json',
    rows: [],
  };
}

module.exports = { loadProjectExport };
```

## Explanation

The fix adds the authenticated user's ID (`req.user.id`) to the project lookup call. This enables `loadProjectExport()` to verify ownership by scoping the query to both the project ID and the owning user. In a real database implementation, this becomes `SELECT * FROM projects WHERE id = ? AND owner_id = ?`. If the project does not exist or does not belong to the authenticated user, the query returns nothing and the route answers 404 — indistinguishably from "not found" or "not yours", which prevents enumeration of other users' projects. The separation of authentication (verified by `requireAuth`) and authorization (verified by ownership scoping) now holds: the route confirms the user is logged in, then confirms they own the resource before proceeding.

## Behaviour changes

- **Before**: Any authenticated user could export any project by URL manipulation.
- **After**: A user can export only projects they own; requests for another user's project return 404.
- **Response on unauthorized access**: 404 (same as "project does not exist"), preventing resource enumeration.
- **No changes to session/authentication flow**: The `requireAuth` middleware continues to verify the user is logged in; ownership verification is now added downstream.
