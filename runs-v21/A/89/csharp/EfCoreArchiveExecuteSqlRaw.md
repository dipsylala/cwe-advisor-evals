## Verdict

**CONFIRMED**: CWE-89 SQL injection through unsanitized string interpolation of user inputs in raw SQL query at line 20.

## Source

The vulnerability exists in `OrderMaintenanceRepository.ArchiveOrdersAsync()`. User-controlled inputs `accountId` and `status` (originating from the HTTP request body in `ArchiveController`) are interpolated directly into the SQL string using string interpolation syntax. While `beforeUtc` is correctly parameterized, `accountId` and `status` are concatenated as string literals into the SQL command, allowing an attacker to inject SQL syntax via these parameters.

**Call chain**: ArchiveController → ArchiveService → OrderMaintenanceRepository.ArchiveOrdersAsync() → ExecuteSqlRawAsync()

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
            "UPDATE Orders SET Archived = 1 WHERE AccountId = @AccountId " +
            "AND Status = @Status AND CreatedAt < @BeforeUtc";

        return _db.Database.ExecuteSqlRawAsync(sql, accountId, status, beforeUtc);
    }
}

public sealed class OrdersDbContext : DbContext
{
}
```

## Explanation

The fix converts the SQL string from string interpolation to a parameterized query:

1. **Remove string interpolation**: Changed from `$"..."` to a plain string with SQL parameter placeholders (`@AccountId`, `@Status`, `@BeforeUtc`).

2. **Replace concatenated values**: All user inputs previously embedded as string literals (`'{accountId}'`, `'{status}'`) are now represented as named parameters in the SQL command.

3. **Pass parameters to ExecuteSqlRawAsync**: Added `accountId, status` to the method call alongside the already-present `beforeUtc` parameter. EF Core matches these positional arguments to the `@`-prefixed parameter placeholders in the SQL string in order.

Parameterized queries ensure that user input is treated as data values, not executable SQL code. The database driver handles escaping and quoting automatically, eliminating the injection vector.
