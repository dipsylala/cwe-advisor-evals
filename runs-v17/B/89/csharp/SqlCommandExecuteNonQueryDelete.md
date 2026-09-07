## Verdict

Exploitable. The data flow is clear: untrusted HTTP request parameters (`tenantId` from the URL route and `beforeDate` from the query string) flow through `AdminCleanupController.DeleteLogs()` to `CleanupRepository.DeleteLogs()`, where they are directly concatenated into a SQL DELETE query without parameterization, creating a SQL injection sink in `SqlCommand.ExecuteNonQuery()` at line 18.

## Source

HTTP request parameters in `AdminCleanupController`:
- `tenantId`: extracted from the URL route parameter `{tenantId}` in the `[HttpDelete("tenant/{tenantId}/logs")]` attribute
- `before`: extracted from the query string via `[FromQuery] string before` and passed to the repository as `beforeDate`

Both values flow unvalidated through the controller to `CleanupRepository.DeleteLogs(string tenantId, string beforeDate)`.

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
        var sql = "DELETE FROM AuditLogs WHERE TenantId = @TenantId AND CreatedAt < @BeforeDate";
        using var command = new SqlCommand(sql, _connection);
        command.Parameters.Add("@TenantId", SqlDbType.NVarChar).Value = tenantId;
        command.Parameters.Add("@BeforeDate", SqlDbType.NVarChar).Value = beforeDate;
        return command.ExecuteNonQuery();
    }
}
```

## Explanation

The vulnerability was eliminated by replacing string concatenation with parameterized queries. The original code constructed SQL by concatenating the untrusted parameters directly into the query string, allowing attackers to inject SQL fragments by supplying values like `' OR '1'='1` or `'; DROP TABLE AuditLogs; --`. 

The fixed code uses placeholder syntax (`@TenantId` and `@BeforeDate`) in the SQL string and binds the parameter values separately via `command.Parameters.Add()`. The SQL Server driver treats the bound values as data, not as executable SQL, preventing injection attacks. The `System.Data` namespace import provides `SqlDbType` which explicitly declares the parameter types as `NVarChar` to match the string inputs.

## Behaviour changes

- **Added import**: `using System.Data;` now included to access the `SqlDbType` enum.
- **SQL string changed**: The query string no longer contains string concatenation with user values. Single quotes were removed from the SQL literals and replaced with parameterized placeholders.
- **Parameter binding added**: Two calls to `command.Parameters.Add()` now bind the `tenantId` and `beforeDate` values to their respective parameters. The return value from `Parameters.Add()` is used to assign the `.Value` property.
- **Function signature unchanged**: The method still accepts the same parameters and returns the same `int` value from `ExecuteNonQuery()`.
- **Sink contract preserved**: `ExecuteNonQuery()` still returns the number of affected rows and throws the same exceptions on database errors. No other behavior of the method is altered.
