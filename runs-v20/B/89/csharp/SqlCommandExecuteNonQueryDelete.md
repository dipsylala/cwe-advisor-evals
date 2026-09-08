## Verdict

Exploitable (CWE-89, SQL Injection). Confidence: high.

## Source

- **Source:** `AdminCleanupController.DeleteLogs` — `tenantId` (route segment `tenant/{tenantId}/logs`) and `before` (`[FromQuery] string before`), both attacker-controlled HTTP input, passed unchanged into `_repository.DeleteLogs(tenantId, before)`.
- **Flow:** `CleanupRepository.DeleteLogs(string tenantId, string beforeDate)` builds `sql` by directly concatenating both parameters into a `DELETE` statement with `+`, with no validation or escaping in between.
- **Sink:** `new SqlCommand(sql, _connection)` followed by `command.ExecuteNonQuery()` (`CleanupRepository.cs` line 18) executes the concatenated string as-is. Either parameter can close the quoted literal it sits in and append arbitrary SQL (e.g. `tenantId = "' OR '1'='1"` deletes every tenant's logs; further UNION/stacked clauses are possible depending on driver/server support).
- **Sink contract (pre-fix):** returns `int` (rows affected) to the controller, which wraps it in `{ deleted }`; discards nothing; leaves no `SqlCommand` arguments implicit beyond the two-arg constructor; on failure lets `SqlException`/`ArgumentException` propagate uncaught. A `null` value for either string concatenates as empty text (C# `string + null` yields the non-null operand unchanged), so the pre-fix code never throws on null input — it just produces `TenantId = ''` / `CreatedAt < ''`.

## Fix

### File: CleanupRepository.cs

```csharp
using System.Data;
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
        command.Parameters.Add("@TenantId", SqlDbType.NVarChar, 100).Value = tenantId ?? string.Empty;
        command.Parameters.Add("@BeforeDate", SqlDbType.NVarChar, 50).Value = beforeDate ?? string.Empty;
        return command.ExecuteNonQuery();
    }
}
```

## Explanation

The query text is now the fixed literal `DELETE FROM AuditLogs WHERE TenantId = @TenantId AND CreatedAt < @BeforeDate`, with `tenantId` and `beforeDate` bound as separate `SqlParameter` values via `command.Parameters.Add(name, SqlDbType, size).Value = ...` rather than spliced into the SQL text. SQL Server always treats a bound parameter's contents as a literal value, never as query syntax, so a value like `' OR '1'='1` or a stacked `; DROP TABLE ...` can no longer alter the statement's structure — it is only ever compared as data. Both parameters are typed `SqlDbType.NVarChar` (matching the guidance's preference for an explicit type over `AddWithValue`) rather than a numeric or date type, because the original code compared these values as string literals and SQL Server's implicit string-to-datetime conversion for `CreatedAt < @BeforeDate` behaves the same way it did in the concatenated original — this fix closes the injection without changing how the date comparison itself is evaluated. `SqlDbType` requires `using System.Data;`, added alongside the existing `using System.Data.SqlClient;`.

## Behaviour changes

- **Null-argument handling:** `SqlParameter.Value` does not accept a CLR `null` the way string concatenation silently did (it must be `DBNull.Value` or the parameter throws at execute time). The fix coalesces `tenantId ?? string.Empty` and `beforeDate ?? string.Empty` so a `null` argument continues to produce the same effective value (`''`) that the original concatenation produced, preserving the pre-fix null behaviour rather than introducing a new runtime exception.
- **Return value, discards, and failure behaviour are unchanged:** `ExecuteNonQuery()` still returns the affected-row count as `int`, no output is newly surfaced or newly suppressed, and unhandled `SqlException` on execute-time errors (e.g. a `beforeDate` value SQL Server cannot convert to a date) still propagates exactly as before — parameterization does not change what the database does with the value once bound, only how it reaches the database.
- All other code (the constructor, the connection field, `AdminCleanupController`) is unchanged.

**Verification:** Compiled with `dotnet build` (net10.0 SDK, `System.Data.SqlClient` 4.9.1 restored from nuget.org) against the fixed file plus a trivial entry point in an isolated scratch project (not the case directory). Result: build succeeded, 0 errors — only the 3 pre-existing `CS0618` "obsolete: use Microsoft.Data.SqlClient" warnings on `SqlConnection`/`SqlCommand`, which are present in the original file's API choice and unrelated to this fix.

**Assumptions:** `beforeDate` is kept as a string parameter (not parsed to `DateTime`) to preserve the original method signature and the original string-comparison semantics against `CreatedAt`; no size was specified in the guidance for `TenantId`/`CreatedAt`, so `NVarChar(100)`/`NVarChar(50)` were chosen as generous, non-truncating bounds for typical identifier/date-string lengths — confirm against the actual `AuditLogs` schema.
