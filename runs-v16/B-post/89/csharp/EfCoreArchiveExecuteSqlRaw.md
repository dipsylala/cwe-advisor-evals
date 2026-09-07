## Verdict
exploitable

## Source
Untrusted user input from HTTP request body: `ArchiveRequest.AccountId` and `ArchiveRequest.Status` in ArchiveController.Archive() (line 19 of ArchiveController.cs) flow through ArchiveService.ArchiveAsync() (line 14 of ArchiveService.cs) to OrderMaintenanceRepository.ArchiveOrdersAsync() where they are concatenated into an SQL query.

## Fix
**Vulnerable code** (OrderMaintenanceRepository.cs, lines 16-20):
```csharp
var sql =
    $"UPDATE Orders SET Archived = 1 WHERE AccountId = '{accountId}' " +
    $"AND Status = '{status}' AND CreatedAt < @beforeUtc";

return _db.Database.ExecuteSqlRawAsync(sql, beforeUtc);
```

**Fixed code**:
```csharp
return _db.Database.ExecuteSqlInterpolatedAsync(
    $"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} " +
    $"AND Status = {status} AND CreatedAt < {beforeUtc}");
```

## Explanation
The vulnerability occurs because `accountId` and `status` are embedded directly into the SQL string via string interpolation with `ExecuteSqlRawAsync`, treating user input as SQL code rather than data. An attacker can inject SQL operators and logic (e.g., `' OR '1'='1`) to bypass the WHERE clause and alter unintended records. The fix uses Entity Framework Core's `ExecuteSqlInterpolatedAsync` method, which accepts a `FormattableString` and automatically parameterizes all interpolated values, ensuring they are sent to the database as data parameters rather than SQL code. This is the primary defence mechanism for SQL injection in Entity Framework Core when raw SQL execution is necessary.

## Behaviour changes
None. `ExecuteSqlInterpolatedAsync` returns `Task<int>` (rows affected) exactly as `ExecuteSqlRawAsync` does. The method signature is compatible with the existing code's return type and call site expectations.
