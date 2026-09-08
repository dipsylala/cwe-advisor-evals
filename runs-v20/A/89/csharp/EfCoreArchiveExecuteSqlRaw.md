## Verdict

Confirmed. `OrderMaintenanceRepository.ArchiveOrdersAsync` builds a SQL `UPDATE` statement by directly interpolating `accountId` and `status` into a C# string, then executes it with `Database.ExecuteSqlRawAsync`. Both values originate from the HTTP request body (`ArchiveRequest.AccountId` / `ArchiveRequest.Status`, via `ArchiveController.Archive` -> `ArchiveService.ArchiveAsync`) with no validation or encoding, so an attacker can close the quoted literal and inject arbitrary SQL (e.g. altering the `WHERE` clause, chaining statements, or exfiltrating data via subqueries).

## Source

`ArchiveController.Archive([FromBody] ArchiveRequest request)` in `ArchiveController.cs` receives `request.AccountId` and `request.Status` from the untrusted request body and passes them unchanged through `ArchiveService.ArchiveAsync` to `OrderMaintenanceRepository.ArchiveOrdersAsync`, where they reach the sink at line 18-20 of `OrderMaintenanceRepository.cs`:

```
var sql =
    $"UPDATE Orders SET Archived = 1 WHERE AccountId = '{accountId}' " +
    $"AND Status = '{status}' AND CreatedAt < @beforeUtc";

return _db.Database.ExecuteSqlRawAsync(sql, beforeUtc);
```

`beforeUtc` is already passed safely as a parameter (`@beforeUtc`); `accountId` and `status` are not.

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
        FormattableString sql =
            $"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} " +
            $"AND Status = {status} AND CreatedAt < {beforeUtc}";

        return _db.Database.ExecuteSqlInterpolatedAsync(sql);
    }
}

public sealed class OrdersDbContext : DbContext
{
}
```

## Explanation

The vulnerable pattern is building the SQL text with string interpolation (`$"...'{accountId}'..."`) and handing the finished string to `ExecuteSqlRawAsync`, which executes it verbatim - `accountId` and `status` land inside the query as literal text, not as data, so a value such as `' OR '1'='1` (or one ending in `'; DROP TABLE Orders; --`) changes the statement's logic or chains additional commands.

The fix keeps the same interpolated-string syntax but changes the type from `string` to `FormattableString` and calls `Database.ExecuteSqlInterpolatedAsync` instead of `ExecuteSqlRawAsync`. EF Core's `ExecuteSqlInterpolatedAsync` overload takes the `FormattableString` apart itself: each `{ }` placeholder becomes a provider-specific `DbParameter` bound by position, and the literal segments become the parameterized command text - functionally identical to how `beforeUtc` was already being passed via `@beforeUtc`, but now applied to every interpolated value instead of just one. The surrounding single quotes around `{accountId}` and `{status}` are removed because the generated parameter is bound as a typed value, not spliced into a quoted string literal - keeping the quotes would pass a parameter whose value still had to be treated as text, which is harmless here but is not the pattern this API expects.

No validation or allowlisting was added: `AccountId` and `Status` are free-form business identifiers whose legal format is a product decision, not a security boundary, and the parameterized call already removes the injection vector for any value they can legally take.

To verify: call `ArchiveOrdersAsync` with `accountId = "' OR '1'='1"` against a seeded `Orders` table - before the fix this updates every row (or throws once the trailing structure is unbalanced); after the fix it matches zero rows because the value is bound as literal data with no matching `AccountId`, and confirm a normal well-formed `accountId`/`status` pair still updates the expected rows.
