## Verdict
exploitable

## Source
ArchiveController.Archive() receives untrusted input (request.AccountId, request.Status) from the request body and passes it to ArchiveService, which forwards it to OrderMaintenanceRepository.ArchiveOrdersAsync().

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
        return _db.Database.ExecuteSqlAsync($"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} AND Status = {status} AND CreatedAt < {beforeUtc}");
    }
}

public sealed class OrdersDbContext : DbContext
{
}
```

## Explanation
The vulnerability occurs because the original code concatenates untrusted string parameters (accountId and status) directly into the SQL query using string interpolation, while only the DateTime parameter (beforeUtc) was passed as a parameter. This allows SQL injection attacks where an attacker could inject arbitrary SQL through the accountId or status fields (e.g., `accountId = "' OR '1'='1"`).

The fix replaces `ExecuteSqlRawAsync()` with `ExecuteSqlAsync()`, which accepts a FormattableString (interpolated string) and automatically parameterizes all interpolated values. Entity Framework Core converts the interpolated string into a parameterized query where all three values (accountId, status, and beforeUtc) are passed as separate parameters rather than concatenated into the SQL string. This ensures that the values are always treated as data, never as executable SQL code, eliminating the injection vulnerability.

## Behaviour changes
The method now uses `ExecuteSqlAsync()` instead of `ExecuteSqlRawAsync()`. The signature of `ExecuteSqlAsync(FormattableString)` differs from `ExecuteSqlRawAsync(string, object[])`:
- Old: Required manually separating SQL string from parameters, with only some parameters properly bound
- New: All interpolated values in the FormattableString are automatically converted to DbParameters by Entity Framework Core
The return type remains `Task<int>`, preserving the contract that returns the number of affected rows.
