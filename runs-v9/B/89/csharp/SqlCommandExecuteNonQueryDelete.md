## Verdict

Exploitable. CWE-89 (SQL Injection), confidence: high.

## Source

`AdminCleanupController.DeleteLogs(string tenantId, [FromQuery] string before)` (`AdminCleanupController.cs:16-21`) - `tenantId` is bound from the route segment `tenant/{tenantId}/logs` and `before` from the `before` query string parameter. Both are attacker-controlled and pass unvalidated into `_repository.DeleteLogs(tenantId, before)`.

## Fix

Sink: `CleanupRepository.DeleteLogs`, `CleanupRepository.cs:14-19`, `SqlCommand.ExecuteNonQuery()` at line 18.

Vulnerable code:

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
        // Vulnerable: tenantId and beforeDate are concatenated directly into the SQL text
        var sql = "DELETE FROM AuditLogs WHERE TenantId = '" + tenantId + "' AND CreatedAt < '" + beforeDate + "'";
        using var command = new SqlCommand(sql, _connection);
        return command.ExecuteNonQuery();
    }
}
```

Fixed code:

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
        command.Parameters.Add("@TenantId", SqlDbType.NVarChar).Value = tenantId;
        command.Parameters.Add("@BeforeDate", SqlDbType.NVarChar).Value = beforeDate;
        return command.ExecuteNonQuery();
    }
}
```

## Explanation

The original code built the `DELETE` statement by concatenating `tenantId` and `beforeDate` directly into the SQL text, so either value could close the surrounding quote and inject additional SQL - an attacker could supply a `tenantId` such as `x' OR '1'='1` to delete every tenant's audit logs, or append a stacked statement where the driver/database permits it. The fix replaces the concatenated literals with named parameters (`@TenantId`, `@BeforeDate`) bound via `SqlCommand.Parameters.Add` with an explicit `SqlDbType`, so both values are always sent to SQL Server as data and can no longer alter the query's structure. `SqlDbType.NVarChar` is used for both parameters to match the original string comparison semantics - `beforeDate` is left as a string rather than parsed to a `DateTime`/`SqlDbType.DateTime2`, preserving whatever implicit string-to-date conversion the `CreatedAt` column comparison relied on before.

## Behaviour changes

None. `ExecuteNonQuery()` still returns the same affected-row count consumed by the caller, the command still executes against the same connection with default `CommandTimeout`, and no exception handling was added or removed - a malformed value still surfaces as a thrown `SqlException` exactly as before. The only change is that `tenantId` and `beforeDate` are now bound as parameters instead of being embedded in the query text.
