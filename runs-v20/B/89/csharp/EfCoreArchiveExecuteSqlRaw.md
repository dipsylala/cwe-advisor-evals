## Verdict

Exploitable. Confidence: high.

- CWE-89, SQL Injection.
- Location: `OrderMaintenanceRepository.cs`, `ArchiveOrdersAsync` - SQL built at lines 16-18, executed at line 20 via `_db.Database.ExecuteSqlRawAsync(sql, beforeUtc)`.

## Source

- Source: the HTTP request body of `POST api/archive/orders`, deserialized into `ArchiveRequest.AccountId` and `ArchiveRequest.Status` (`ArchiveController.cs` line 17, record declared line 24).
- Flow: `ArchiveController.Archive` passes `request.AccountId` / `request.Status` unchanged to `ArchiveService.ArchiveAsync` (`ArchiveService.cs` line 12-15), which passes them unchanged to `OrderMaintenanceRepository.ArchiveOrdersAsync`. No validation, allowlisting, or escaping occurs anywhere on this path.
- Sink: `OrderMaintenanceRepository.cs` lines 16-20. `accountId` and `status` are interpolated directly into the `UPDATE` statement's string literals (`AccountId = '{accountId}'`, `Status = '{status}'`), so both are executable SQL text by the time the string reaches `ExecuteSqlRawAsync`. Only `beforeUtc` is passed as a bound parameter (`@beforeUtc`); `accountId` and `status` are not parameters of the call at all - an attacker who controls either field can close the quote and rewrite the `WHERE` clause or append further statements.
- Sink contract: `ExecuteSqlRawAsync(string, params object[])` returns a `Task<int>` of affected rows, which the caller chain returns straight back to the controller as JSON (`{ archived }`); it discards nothing; the only implicit argument is the parameter array, currently just `beforeUtc`; on failure it throws (e.g. `Microsoft.Data.SqlClient.SqlException`), unhandled, propagating to the ASP.NET Core default error pipeline - the fix does not change any of this.

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
        System.FormattableString sql =
            $"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} AND Status = {status} AND CreatedAt < {beforeUtc}";

        return _db.Database.ExecuteSqlInterpolatedAsync(sql);
    }
}

public sealed class OrdersDbContext : DbContext
{
}
```

## Explanation

The vulnerable code built the `UPDATE` statement with C# string interpolation (`$"...{accountId}..."`) and handed the finished string to `ExecuteSqlRawAsync`, so `accountId` and `status` became part of the SQL text rather than data. The fix keeps the same statement shape and the same non-query call family but switches to `Database.ExecuteSqlInterpolatedAsync(FormattableString)`, EF Core's parameterizing counterpart to `ExecuteSqlRaw`. Because the whole statement is written as a single interpolated string literal assigned to a `FormattableString`-typed variable, the compiler routes it through `FormattableString.Create` instead of `string.Format`; EF Core's relational provider then converts every `{...}` hole - `accountId`, `status`, and `beforeUtc` alike - into its own `DbParameter` before sending the command, so none of the three can be interpreted as SQL syntax regardless of what characters they contain.

## Behaviour changes

- None beyond closing the weakness. The method's signature, return type (`Task<int>` affected-row count), the statement's logic (same three `WHERE` conditions, same `SET Archived = 1`), and failure behaviour (exceptions still propagate uncaught) are unchanged; `beforeUtc`, already a bound parameter before the fix, remains one.
- Verification: compiled standalone against the real `Microsoft.EntityFrameworkCore.Sqlite` 10.0.11 NuGet package with `dotnet build` (.NET SDK 10.0.203) in a scratch project outside the repository - build succeeded with 0 errors, confirming `Database.ExecuteSqlInterpolatedAsync(FormattableString)` exists on `DatabaseFacade` and that the single-interpolated-string-literal-to-`FormattableString` target typing compiles as written (a `+`-concatenated pair of interpolated strings would not have, since only a single interpolated string literal is eligible for that conversion - this is why the fix restates the statement as one literal instead of preserving the original's two-line concatenation).
- Assumptions: none - `ExecuteSqlInterpolatedAsync` is the language guidance's named non-query parameterizing counterpart to `FromSqlInterpolated`, and no library version change was needed since the project already references EF Core.
