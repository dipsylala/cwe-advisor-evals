## Verdict

Confirmed. `CleanupRepository.DeleteLogs` builds the `DELETE` statement by directly concatenating `tenantId` and `beforeDate` into the SQL text, so either value can inject arbitrary SQL that `SqlCommand.ExecuteNonQuery()` will execute verbatim.

## Source

`AdminCleanupController.DeleteLogs(string tenantId, [FromQuery] string before)` — `tenantId` is a route segment and `before` is a query-string parameter on `DELETE admin/cleanup/tenant/{tenantId}/logs`, both fully attacker-controlled. They flow unchanged into `CleanupRepository.DeleteLogs(tenantId, before)`.

## Fix

### File: CleanupRepository.cs
```csharp
using System;
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
        if (!DateTime.TryParse(beforeDate, out var before))
        {
            throw new ArgumentException("Invalid date value.", nameof(beforeDate));
        }

        const string sql = "DELETE FROM AuditLogs WHERE TenantId = @TenantId AND CreatedAt < @CreatedBefore";
        using var command = new SqlCommand(sql, _connection);
        command.Parameters.Add("@TenantId", SqlDbType.NVarChar, 100).Value = tenantId;
        command.Parameters.Add("@CreatedBefore", SqlDbType.DateTime2).Value = before;
        return command.ExecuteNonQuery();
    }
}
```

## Explanation

The DELETE statement is now built with fixed SQL text and two bound parameters (`@TenantId`, `@CreatedBefore`) instead of string concatenation, so `SqlClient` sends `tenantId` and the parsed date as data values rather than as part of the command text — no attacker-supplied quote, comment marker, or statement separator can change the query's structure.

`beforeDate` is additionally parsed with `DateTime.TryParse` before binding. This is a correctness/defence-in-depth step, not the primary fix: the parameterization alone already neutralizes injection, but converting the value to a real `DateTime` (bound as `SqlDbType.DateTime2`) also rejects malformed input outright rather than letting a non-date string reach the database as an odd literal. `tenantId` is bound as `SqlDbType.NVarChar` with an explicit length to match typical tenant-identifier columns; adjust the length to the actual schema if it differs.
