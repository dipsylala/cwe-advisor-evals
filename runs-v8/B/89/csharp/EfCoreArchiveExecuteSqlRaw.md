## Verdict

Exploitable. Untrusted user input from the HTTP request (accountId and status) is directly interpolated into the SQL query string without parameterization and passed to ExecuteSqlRawAsync, allowing SQL injection attacks.

## Source

**Call chain:**
- ArchiveController.Archive() receives accountId and status from HTTP POST request body (ArchiveRequest)
- Passes to ArchiveService.ArchiveAsync()
- Passes to OrderMaintenanceRepository.ArchiveOrdersAsync()
- **Vulnerable point (line 20):** SQL query is constructed using string interpolation with accountId and status embedded directly, then executed via ExecuteSqlRawAsync

**Attack scenario:**
An attacker submits a POST request with `"accountId": "1' OR '1'='1"`, modifying the query logic to archive all orders regardless of account ID.

## Fix

```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    var sql =
        "UPDATE Orders SET Archived = 1 WHERE AccountId = {0} " +
        "AND Status = {1} AND CreatedAt < {2}";

    return _db.Database.ExecuteSqlRawAsync(sql, accountId, status, beforeUtc);
}
```

## Explanation

The vulnerable code embedded `accountId` and `status` directly into the SQL string using string interpolation (with single quotes), making them indistinguishable from SQL syntax. An attacker could inject SQL operators or logic to break out of the intended WHERE clause.

The fix converts all three values to positional parameters using `{0}`, `{1}`, and `{2}` placeholders. Entity Framework Core's ExecuteSqlRawAsync automatically treats these parameter positions as data values, not SQL code, preventing injection. All user-supplied values are now passed as parameters rather than embedded in the SQL string.

## Behaviour changes

The query now uses parameterized positions (`{0}`, `{1}`, `{2}`) instead of embedding values with single quotes. The ExecuteSqlRawAsync method returns the same type (Task<int>), receives the same parameters in the same order, and produces the same result set—it updates the same rows with the same WHERE conditions. No functional behavior changes; only the mechanism by which values reach the database is secured.
