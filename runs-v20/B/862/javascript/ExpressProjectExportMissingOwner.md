## Verdict

Exploitable. CWE-862 (Missing Authorization), confidence: high.

`GET /projects/:projectId/export` runs `requireAuth`, which only confirms `req.user` is set (authentication), then calls `loadProjectExport(req.params.projectId)` and returns whatever comes back. The lookup is keyed solely on the attacker-controlled `:projectId` path parameter with no check that the authenticated caller owns, or is otherwise granted access to, that project. Any authenticated user can enumerate `projectId` values and receive another user's export data.

## Source

- **Source**: `req.params.projectId` (attacker-controlled route parameter) and `req.user` (trusted, set by upstream session middleware and checked only for presence by `requireAuth` in `sessionAuth.js`).
- **Sink**: `loadProjectExport(projectId)` in `projectStore.js`, called from the route handler in `projectRoutes.js` line 9-10.
- **Call chain**: `projectRoutes.js` (`router.get('/projects/:projectId/export', requireAuth, handler)`) -> `sessionAuth.js` `requireAuth` (authenticates only, `next()`s with no role/ownership check) -> `projectStore.js` `loadProjectExport(projectId)` (loads and returns export data for any `projectId`, with no owner or permission argument at all).
- The break: `requireAuth` only gates on "is someone logged in." Nothing between it and the data return checks that `req.user` is entitled to `req.params.projectId` specifically. `loadProjectExport`'s contract takes no caller-identity input, so the vulnerability cannot be closed at the route layer alone - the lookup itself has to be scoped.

## Fix

### File: projectRoutes.js
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

### File: projectStore.js
```javascript
'use strict';

// Stand-in for the persistence layer. A real implementation replaces
// this map with a database query scoped by owner, e.g.:
//   db.collection('projects').findOne({ _id: projectId, ownerId })
const projectsById = new Map([
  ['proj-1001', { id: 'proj-1001', ownerId: 'user-1', rows: [] }],
]);

async function loadProjectExport(projectId, ownerId) {
  const project = projectsById.get(projectId);
  if (!project || project.ownerId !== ownerId) {
    return null;
  }

  return {
    projectId: project.id,
    format: 'json',
    rows: project.rows,
  };
}

module.exports = { loadProjectExport };
```

## Explanation

The fix threads the authenticated caller's identity (`req.user.id`) into the resource lookup instead of relying on `requireAuth`'s login check alone, following the CWE-862 JavaScript guidance's scoped-query pattern (`findOne({ _id: id, ownerId })`) rather than loading by ID and comparing afterward. `loadProjectExport` now takes an `ownerId` parameter and only returns export data when the located record's `ownerId` matches the caller; any mismatch - project not found, or found but owned by someone else - returns `null` through the exact same path, so the route's existing `404 { error: 'not_found' }` response is unchanged and identical for both cases. This prevents the object-level access-control bypass: an authenticated user can no longer read another user's export by guessing or iterating `projectId` values, and the "not found" response gives no signal distinguishing a nonexistent project from one that exists but isn't theirs.

The in-memory `projectsById` map replaces the prior unconditional fabrication (which returned data for any `projectId`) and stands in for the real datastore this fixture elides; a production implementation swaps it for the actual scoped database/ORM query named above without changing `loadProjectExport`'s signature or the route's handling of its result.

**Verification**: `node --check` on both files in a scratch copy outside the case directory - both passed with no diagnostics. Traced by hand: `loadProjectExport`'s new second parameter is supplied at its only call site (`projectRoutes.js`); `projectsById`, `project.ownerId`, and `project.id` are all defined in the same file, so no unverified names were introduced; `sessionAuth.js` is untouched and its `requireAuth` contract (401 with `{ error: 'unauthorized' }` when `req.user` is absent) is unaffected.

## Behaviour changes

- `loadProjectExport` signature changed from `(projectId)` to `(projectId, ownerId)`. Required: the scoping check needs the caller's identity, which the original contract never received.
- Call site in `projectRoutes.js` now passes `req.user.id` as the second argument. Assumption: `req.user` carries an `id` field identifying the authenticated user (the common convention for session-based middleware named `sessionAuth`, though `sessionAuth.js` itself never declares the shape of `req.user` - this is recorded as an assumption, not verified against a real session layer). If the codebase's real `req.user` uses a different identifier field (e.g. `userId`, `_id`), the call site should use that field instead.
- `projectStore.js`'s internal data source changed from unconditional fabrication (any `projectId` returns a payload) to a scoped lookup against a small persistence stand-in. This means a `projectId` that isn't present in the real backing store, or that the backing store's real query does not attribute to the caller, now correctly returns `null` -> 404, whereas before it always returned data. This is the intended effect of the fix, not incidental: closing an ownership bypass necessarily removes the "return data for any ID" behaviour it depended on.
- No change to the 401 path, response shapes, or `sessionAuth.js`.

Assumption made without a human to confirm: `req.user.id` is the correct property for the authenticated user's identifier; `sessionAuth.js` only checks `req.user` for truthiness and does not define its shape, so this is inferred from common Express/session middleware convention rather than confirmed in the provided files - if the real `req.user` uses a different field (e.g. `userId`, `_id`), the call site should use that field instead. Also assumed: the real backing store behind `projectStore.js` (elided in this fixture) implements the `ownerId` predicate as part of its actual query, per the CWE-862 JavaScript guidance's `findOne({ _id: id, ownerId })` pattern; the in-memory map here is illustrative of that contract, not a production persistence layer.
