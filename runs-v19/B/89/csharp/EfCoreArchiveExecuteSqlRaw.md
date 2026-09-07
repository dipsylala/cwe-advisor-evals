## Verdict

SQL injection vulnerability confirmed. Untrusted HTTP request parameters `accountId` and `status` are directly interpolated into the SQL query string without parameterization, allowing attackers to manipulate query logic.

## Source

**ArchiveController.cs (line 17-19)**: HTTP POST endpoint receives untrusted `ArchiveRequest` from client:
- `request.AccountId`
- `request.Status`

**ArchiveService.cs (line 14)**: Passes parameters unchanged to repository.

**OrderMaintenanceRepository.cs (lines 16-20)**: Constructs SQL query by directly interpolating untrusted parameters into the query string, then executes it.

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
        return _db.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} AND Status = {status} AND CreatedAt < {beforeUtc}");
    }
}

public sealed class OrdersDbContext : DbContext
{
}
```

## Explanation

The fix replaces `ExecuteSqlRawAsync()` with `ExecuteSqlInterpolatedAsync()` and removes the intermediate string concatenation. `ExecuteSqlInterpolatedAsync()` automatically wraps each interpolated value in a `DbParameter`, ensuring all user input is treated as data rather than query structure. This eliminates the injection vector.

The fixed code removes the manual string interpolation (`'{accountId}'` becomes `{accountId}`), allowing Entity Framework Core to handle parameterization. All three values—`accountId`, `status`, and `beforeUtc`—are now passed as safe parameters to the database.

## Behaviour changes

None. The query logic remains identical; only the mechanism of passing parameters is changed. The UPDATE statement still filters on the same three conditions and returns the same integer count of affected rows.
