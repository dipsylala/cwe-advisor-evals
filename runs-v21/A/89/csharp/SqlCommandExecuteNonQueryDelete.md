## Verdict
CONFIRMED - SQL injection via unparameterized string concatenation.

## Source
`AdminCleanupController.DeleteLogs()` receives `tenantId` from the route and `before` from the query string, then passes both to `CleanupRepository.DeleteLogs()`. The repository concatenates these values directly into a SQL DELETE statement without parameterization, allowing an attacker to inject arbitrary SQL syntax and modify or delete unintended records.

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
        command.Parameters.AddWithValue("@TenantId", tenantId ?? "");
        command.Parameters.AddWithValue("@BeforeDate", beforeDate ?? "");
        return command.ExecuteNonQuery();
    }
}
```

## Explanation
Replace string concatenation with parameterized query placeholders (@TenantId and @BeforeDate). Use `SqlCommand.Parameters.AddWithValue()` to bind the user-supplied values as parameters. SqlClient then treats the values as data, not executable SQL syntax, preventing injection. The null-coalescing operators (`?? ""`) handle the case where either parameter is null, converting it to an empty string for the database layer.
