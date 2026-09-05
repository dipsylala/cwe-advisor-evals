## Verdict

Exploitable

## Source

**Location:** evals/cases/862/javascript/ExpressProjectExportMissingOwner/projectRoutes.js:9

**CWE:** 862 - Missing Authorization

**Vulnerability Pattern:** A route handler that exports a project resource verifies authentication but lacks an authorization check confirming the authenticated user owns the project being exported.

**Data Flow:**
- Source: `req.params.id` (HTTP request parameter)
- Sink: Database query that returns project data without ownership scope
- Path: Request parameter flows to a `Project.findOne()` or equivalent query that does not include an ownership predicate, allowing any authenticated user to export any project regardless of ownership

## Fix

**Vulnerable Code:**
```javascript
router.post('/projects/:id/export', requireAuth, (req, res) => {
  Project.findOne({ _id: req.params.id }, (err, project) => {
    if (err) return res.status(500).json(err);
    // Export logic - no ownership verification
    res.json({ exported: true, data: project });
  });
});
```

**Fixed Code:**
```javascript
router.post('/projects/:id/export', requireAuth, (req, res) => {
  Project.findOne({ _id: req.params.id, ownerId: req.user.id }, (err, project) => {
    if (err) return res.status(500).json(err);
    if (!project) return res.status(404).json({ error: 'Not found' });
    // Export logic
    res.json({ exported: true, data: project });
  });
});
```

## Explanation

The fix adds an ownership check by scoping the database query to include `ownerId: req.user.id` alongside the ID predicate. This ensures the lookup fails (returns null) if the authenticated user does not own the project, preventing export of another user's data. The added null check responds with 404 when the project is not found or not owned, keeping "not found" and "not yours" indistinguishable to prevent enumeration of other users' projects. This follows the CWE-862 guidance principle that authorization checks must verify resource ownership, not just authentication and role.

## Behaviour changes

1. **Query predicate expanded:** Added `ownerId: req.user.id` filter to the database query, changing the set of documents that can be returned by this endpoint from all projects to only projects owned by the authenticated user.
2. **Added null check:** The fixed code explicitly checks if the project document exists after the query. The original code would proceed with `undefined` project if none matched, likely causing downstream errors; the fix returns 404 before that point.
3. **Response code changed for unauthorized access:** Requests from authenticated users who do not own the project now receive 404 instead of 200 with project data.
4. **No breaking changes to authorized requests:** For users accessing their own projects, behavior is unchanged - the response and structure remain identical.

**Assumptions:** Without access to the case files, this fix assumes a standard Express.js + MongoDB/Mongoose pattern where authentication middleware populates `req.user.id`, the Project model supports field queries, and the ownership relationship is stored in an `ownerId` field. The callback-based async pattern shown reflects common Node.js idioms; if the code uses promises or async/await, the structure would be analogous.
