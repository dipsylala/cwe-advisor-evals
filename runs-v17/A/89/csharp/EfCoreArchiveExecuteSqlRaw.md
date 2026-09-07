## Verdict

The vulnerability is confirmed. The code uses string interpolation to embed user-supplied `accountId` and `status` parameters directly into a SQL query string, enabling SQL injection attacks.

## Source

The vulnerable call chain:
1. **ArchiveController.cs** receives user input via the POST request body (AccountId and Status)
2. **ArchiveService.cs** passes these parameters to the repository
3. **OrderMaintenanceRepository.cs** line 20 uses `ExecuteSqlRawAsync()` with a SQL string constructed via string interpolation on lines 16-18, embedding the untrusted parameters directly into the query

## Fix

### File: OrderMaintenanceRepository.cs

```csharp
using Microsoft.EntityFrameworkCore;

namespace Cases.SqlInjection;

public sealed class OrderMaintenanceRepository
{
    private readonly OrdersDbContext _db;

    public OrderMaintenanceRepository(OrdersDbContext db)
    {
        _db = db;
    }

    public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
    {
        var sql =
            "UPDATE Orders SET Archived = 1 WHERE AccountId = @accountId " +
            "AND Status = @status AND CreatedAt < @beforeUtc";

        return _db.Database.ExecuteSqlRawAsync(sql, accountId, status, beforeUtc);
    }
}

public sealed class OrdersDbContext : DbContext
{
}
```

## Explanation

The fix replaces string interpolation with parameterized queries. Instead of embedding `{accountId}` and `{status}` into the SQL string via string interpolation, the corrected code:

1. Uses SQL parameter placeholders: `@accountId`, `@status`, and `@beforeUtc` in the query string
2. Passes all parameter values as separate arguments to `ExecuteSqlRawAsync()`, not as part of the SQL string
3. The database driver now treats these values as data, not executable SQL code, preventing SQL injection regardless of the input content

The original code only parameterized the `beforeUtc` value (via `@beforeUtc`), while leaving `accountId` and `status` vulnerable to injection. The fix parameterizes all three values consistently, applying defense-in-depth through proper parameterization of all user-supplied input.
