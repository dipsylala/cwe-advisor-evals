## Verdict
Exploitable - SQL Injection via string concatenation of untrusted parameters in DELETE query.

## Source
`tenantId` and `before` parameters flow from the HTTP route and query string in `AdminCleanupController.DeleteLogs()` → `CleanupRepository.DeleteLogs()`.

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
        var sql = "DELETE FROM AuditLogs WHERE TenantId = @tenantId AND CreatedAt < @beforeDate";
        using var command = new SqlCommand(sql, _connection);
        command.Parameters.Add("@tenantId", SqlDbType.NVarChar).Value = tenantId;
        command.Parameters.Add("@beforeDate", SqlDbType.DateTime).Value = beforeDate;
        return command.ExecuteNonQuery();
    }
}
```

## Explanation
The vulnerability was in line 18 of the original `DeleteLogs` method, where the SQL query was built by concatenating `tenantId` and `beforeDate` directly into the SQL string. This allowed an attacker to inject SQL fragments like `' OR '1'='1` to manipulate query logic.

The fix replaces string concatenation with parameterized queries using `SqlCommand.Parameters`. Placeholders (`@tenantId`, `@beforeDate`) stand in for the data values in the query string, and the parameters are added explicitly with their SQL types (`SqlDbType.NVarChar` for the string tenant ID, `SqlDbType.DateTime` for the date). The untrusted input is now passed as parameter values, not as part of the query structure, so it is always treated as data rather than executable SQL.

The `using System.Data;` import is required for `SqlDbType` to be available. The method signature, return type, and behavior remain unchanged.

## Behaviour changes
None. The parameterized query executes the same DELETE logic as the original concatenated query, passes the same parameters to the database, and returns the same row count. The fix preserves the entire sink contract: same return value, same error handling via exception propagation, no discarded output.
