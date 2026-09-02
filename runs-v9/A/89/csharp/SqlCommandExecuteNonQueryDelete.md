## Verdict

Confirmed. `CleanupRepository.DeleteLogs` builds a `DELETE` statement by concatenating `tenantId` and `beforeDate` directly into the SQL text, then executes it with `SqlCommand.ExecuteNonQuery()`. Both values originate from an HTTP request and are fully attacker-controlled, so an attacker can break out of the intended string literals to alter the query's logic (e.g. delete all tenants' logs regardless of date) or chain additional statements.

## Source

- `AdminCleanupController.DeleteLogs(string tenantId, [FromQuery] string before)` — `tenantId` comes from the route segment `tenant/{tenantId}/logs`, `before` comes from the `before` query-string parameter. Neither is validated or escaped.
- Both are passed unchanged into `CleanupRepository.DeleteLogs(tenantId, before)`.
- Sink: `CleanupRepository.DeleteLogs`, line 16-18 — string concatenation into `sql`, then `new SqlCommand(sql, _connection)` and `command.ExecuteNonQuery()`.

## Fix

```csharp
using System.Data.SqlClient;

namespace Cases.SqlInjection;

public sealed class CleanupRepository
{
    private readonly SqlConnection _connection;

    public CleanupRepository(SqlConnection connection)
    {
        _connection = connection;
    }

    public int DeleteLogs(string tenantId, string beforeDate)
    {
        const string sql = "DELETE FROM AuditLogs WHERE TenantId = @TenantId AND CreatedAt < @BeforeDate";
        using var command = new SqlCommand(sql, _connection);
        command.Parameters.Add("@TenantId", SqlDbType.NVarChar, 100).Value = tenantId;
        command.Parameters.Add("@BeforeDate", SqlDbType.DateTime2).Value = DateTime.Parse(beforeDate, CultureInfo.InvariantCulture);
        return command.ExecuteNonQuery();
    }
}
```

(add `using System.Data;` and `using System.Globalization;` alongside the existing `using System.Data.SqlClient;`)

## Explanation

The query text is now a fixed string with no user input woven into it; `tenantId` and `beforeDate` travel to SQL Server as parameter values via `SqlParameter`, so the driver sends them as data rather than as part of the command grammar. A crafted value such as `' OR '1'='1` or a stacked `'; DROP TABLE AuditLogs; --` can no longer change the statement's structure — it can only ever match (or fail to match) the literal `TenantId`/`CreatedAt` comparison.

`beforeDate` is additionally parsed with `DateTime.Parse` before being bound as a `DateTime2` parameter rather than passed through as raw text. This gives a defined, typed failure mode (a `FormatException` on malformed input, which should be caught and turned into a 400 response at the controller boundary) instead of accepting arbitrary strings into a date comparison, and it means the value can never carry SQL syntax regardless of how it is later used. Sizing `@TenantId` to a bounded `NVARCHAR` length (matching the actual column definition) also prevents oversized input from being silently accepted.

No behavioral change occurs for legitimate callers: the same two logical inputs are still used to filter and delete rows from `AuditLogs`, just supplied through the parameter collection instead of string concatenation.
