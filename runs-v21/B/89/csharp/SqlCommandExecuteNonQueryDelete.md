## Verdict

Exploitable. Untrusted user input from route and query parameters is concatenated directly into an SQL DELETE query without parameterization, allowing an attacker to inject arbitrary SQL commands.

## Source

- `tenantId`: route parameter from `{tenantId}` in AdminCleanupController line 16
- `before`: query string parameter in AdminCleanupController line 17

Both are passed to `CleanupRepository.DeleteLogs(string tenantId, string beforeDate)` on line 19 of AdminCleanupController without validation.

## Sink

`SqlCommand.ExecuteNonQuery()` on line 18 of CleanupRepository.cs. The query string passed to the SqlCommand constructor on line 17 is built via string concatenation on line 16:

```
var sql = "DELETE FROM AuditLogs WHERE TenantId = '" + tenantId + "' AND CreatedAt < '" + beforeDate + "'";
```

Both `tenantId` and `beforeDate` parameters are concatenated directly into the SQL string without escape or parameterization. An attacker controlling these values can break out of the quoted string context and inject SQL syntax.

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
        var sql = "DELETE FROM AuditLogs WHERE TenantId = @tenantId AND CreatedAt < @beforeDate";
        using var command = new SqlCommand(sql, _connection);
        command.Parameters.Add("@tenantId", SqlDbType.NVarChar).Value = tenantId;
        command.Parameters.Add("@beforeDate", SqlDbType.NVarChar).Value = beforeDate;
        return command.ExecuteNonQuery();
    }
}
```

## Explanation

The fix eliminates the SQL injection vulnerability by replacing string concatenation with parameterized queries. The SQL string now contains parameter placeholders (`@tenantId`, `@beforeDate`) instead of directly embedding user input. User-supplied values are passed separately to the database driver via `SqlCommand.Parameters.Add()` with an explicit `SqlDbType.NVarChar` type declaration. This ensures that the database driver treats these values as data literals, not as executable SQL syntax, regardless of what special characters they contain. The method signature, return type, and exception behavior remain unchanged; `ExecuteNonQuery()` continues to return the number of affected rows exactly as before. The addition of `using System.Data;` is required to access the `SqlDbType` enum for type-safe parameter binding.

## Behaviour changes

None. The method signature, parameters, and return type are unchanged. `ExecuteNonQuery()` continues to return the number of rows deleted and may throw `SqlException` on database errors as before. The only change is in how the query is constructed and executed: from concatenation to parameterized binding, which has no observable effect on the method's contract or behavior—only on how safely it handles untrusted input.
