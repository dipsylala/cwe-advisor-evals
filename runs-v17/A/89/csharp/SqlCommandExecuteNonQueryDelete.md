## Verdict
SQL injection vulnerability confirmed. Line 18 in CleanupRepository.cs constructs a SQL DELETE command by concatenating user-supplied strings directly into the query. An attacker controlling either the `tenantId` or `beforeDate` parameters can inject arbitrary SQL code.

## Source
The vulnerable code path flows from `AdminCleanupController.DeleteLogs()` (line 18 of AdminCleanupController.cs), which receives unsanitized `tenantId` and `before` parameters from HTTP inputs (URL path and query string). These are passed to `CleanupRepository.DeleteLogs(string tenantId, string beforeDate)` (line 15 of CleanupRepository.cs), where line 18 concatenates them directly into a SQL DELETE command without parameterization.

## Fix

### File: CleanupRepository.cs

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
        var sql = "DELETE FROM AuditLogs WHERE TenantId = @TenantId AND CreatedAt < @BeforeDate";
        using var command = new SqlCommand(sql, _connection);
        command.Parameters.AddWithValue("@TenantId", tenantId);
        command.Parameters.AddWithValue("@BeforeDate", beforeDate);
        return command.ExecuteNonQuery();
    }
}
```

## Explanation
The fix replaces string concatenation with parameterized queries. The SQL command now contains named parameter placeholders (`@TenantId` and `@BeforeDate`) instead of embedding the raw string values. The actual parameter values are added separately via `SqlCommand.Parameters.AddWithValue()`, which treats them as data rather than executable SQL. This prevents SQL injection because the database driver guarantees that parameter values cannot be interpreted as SQL syntax, regardless of their content.
