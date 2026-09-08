## Verdict

Exploitable SQL injection confirmed. Untrusted user input (accountId, status) from the HTTP request flows to ExecuteSqlRawAsync without parameterization, allowing attackers to inject arbitrary SQL.

## Source

ArchiveController receives user input via HTTP POST body:
- AccountId (string)
- Status (string)
- BeforeUtc (DateTime)

Request is deserialized into ArchiveRequest and passed to ArchiveService.ArchiveAsync, which forwards to OrderMaintenanceRepository.ArchiveOrdersAsync.

## Fix

Replace ExecuteSqlRawAsync with ExecuteSqlInterpolatedAsync to enable automatic parameterization of interpolated values.

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
        return _db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} AND Status = {status} AND CreatedAt < {beforeUtc}");
    }
}

public sealed class OrdersDbContext : DbContext
{
}
```

## Explanation

The original code built SQL by concatenating string interpolations for accountId and status, then passed this concatenated string to ExecuteSqlRawAsync. This treats untrusted input as SQL code rather than data.

ExecuteSqlInterpolatedAsync accepts a FormattableString (created by string interpolation with $) and automatically wraps all interpolated values in DbParameters, preventing SQL injection. The interpolated values are never treated as SQL syntax—they are always passed as parameter values to the database driver.

The fix consolidates the split concatenated string into a single interpolated string. EF Core parameterizes accountId, status, and beforeUtc uniformly, eliminating the injection vector.

## Behaviour changes

None. The query logic, return type, and external contract remain unchanged. All values that were previously supplied to ExecuteSqlRaw (even when partially parameterized via the manual @beforeUtc placeholder) are now parameterized uniformly by EF Core's interpolation handler.
