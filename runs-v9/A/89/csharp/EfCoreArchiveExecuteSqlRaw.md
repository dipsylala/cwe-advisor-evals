## Verdict

Confirmed. `OrderMaintenanceRepository.ArchiveOrdersAsync` builds a raw SQL `UPDATE` statement by
directly interpolating `accountId` and `status` into the string, then executes it with
`ExecuteSqlRawAsync`. Both values originate from the JSON request body (`ArchiveRequest.AccountId`
and `ArchiveRequest.Status`, via `ArchiveController.Archive` -> `ArchiveService.ArchiveAsync`) with
no validation or encoding before reaching the SQL sink. Only `beforeUtc` is parameterized; the
other two fields let an attacker break out of the quoted literals and inject arbitrary SQL (e.g.
`AccountId = "' OR '1'='1"` archives every order, or a stacked/UNION payload can read or modify
unrelated data).

## Source

`ArchiveController.Archive` (`E:/Github/cwe-advisor/evals/cases/89/csharp/EfCoreArchiveExecuteSqlRaw/ArchiveController.cs`,
line 19) receives `request.AccountId` and `request.Status` from the deserialized request body and
passes them unchanged through `ArchiveService.ArchiveAsync`
(`ArchiveService.cs`, line 14) into
`OrderMaintenanceRepository.ArchiveOrdersAsync`
(`OrderMaintenanceRepository.cs`, line 14), where they are interpolated into the SQL text used at
the sink, `ExecuteSqlRawAsync` (line 20).

## Fix

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

`ExecuteSqlRawAsync` executes its `sql` argument as literal text; anything concatenated or
interpolated into that string before the call becomes part of the command, not data, which is why
`accountId` and `status` needed to be quoted by hand and were therefore injectable. Only
`beforeUtc` was safe, because it was passed as a separate parameter (`@beforeUtc`) bound
out-of-band from the command text.

Replacing the manual string with `ExecuteSqlInterpolatedAsync` and a `FormattableString` keeps the
call site's syntax almost identical but changes the semantics: EF Core does not render the
interpolated holes into the SQL text itself. Instead it walks the `FormattableString.GetArguments()`
values and emits a parameterized command, generating a provider-specific parameter (e.g. `p0`,
`p1`) for each interpolated expression and binding `accountId`, `status`, and `beforeUtc` as data
values. This closes the injection path structurally - there is no longer a quoted literal for an
attacker-controlled value to break out of, regardless of what characters `accountId` or `status`
contain (quotes, `--`, `;`, etc. are all just bytes in a bound parameter, never parsed as SQL
syntax).

Do not just remove the manual quotes and re-run the same string through `ExecuteSqlRawAsync` -
`ExecuteSqlRawAsync` never parameterizes interpolated content; it only forwards whatever
`SqlParameter`/positional arguments are passed alongside it. The fix has to route through
`ExecuteSqlInterpolatedAsync` (or, equivalently, keep `ExecuteSqlRawAsync` but rewrite the SQL with
named placeholders and pass `accountId`/`status` as explicit `SqlParameter` arguments) so the
values are bound rather than concatenated.

After the fix, verify with a value such as `AccountId = "' OR '1'='1"`: the previous raw-SQL
version would have archived every row regardless of account; the parameterized version treats the
whole string as a single literal account id, matches no rows (or exactly the literal account, if
one happens to be named that), and no query plan or logged statement shows the injected clause.
