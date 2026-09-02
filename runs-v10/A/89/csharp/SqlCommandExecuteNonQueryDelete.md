## Verdict

SQL injection via string concatenation in `CleanupRepository.DeleteLogs()`. User-supplied `tenantId` and `beforeDate` parameters are embedded directly into the SQL query string without parameterization, allowing an attacker to inject arbitrary SQL commands. The vulnerability is realizable when the controller method routes user input to this repository method.

## Source

The attack surface spans two files:

1. **AdminCleanupController.cs**: Route parameters and query strings from HTTP requests are passed unsanitized to the repository. The `tenantId` path parameter and `before` query parameter originate from untrusted input.

2. **CleanupRepository.cs, line 16**: The `DeleteLogs()` method constructs the SQL query via string concatenation: `"DELETE FROM AuditLogs WHERE TenantId = '" + tenantId + "' AND CreatedAt < '" + beforeDate + "'"`. This concatenation is the vulnerability source.

An attacker can exploit this by crafting requests like `/admin/cleanup/tenant/'-WAITFOR-DELAY-'0:0:5'--/logs?before=2024-01-01`, injecting SQL delays, extraction queries, or destructive operations.

## Fix

Replace string concatenation with parameterized queries using `SqlParameter`:

```csharp
public int DeleteLogs(string tenantId, string beforeDate)
{
    var sql = "DELETE FROM AuditLogs WHERE TenantId = @TenantId AND CreatedAt < @BeforeDate";
    using var command = new SqlCommand(sql, _connection);
    command.Parameters.AddWithValue("@TenantId", tenantId);
    command.Parameters.AddWithValue("@BeforeDate", beforeDate);
    return command.ExecuteNonQuery();
}
```

The `@TenantId` and `@BeforeDate` placeholders in the query ensure the database driver treats the parameter values as data, never as SQL syntax. Parameterization is the primary defence against SQL injection in .NET.

## Explanation

String concatenation treats user input as SQL code, allowing attackers to alter query logic. Parameterized queries (prepared statements) separate query structure from data: the SQL query template is fixed at the database layer, and parameter values are always interpreted as literal data regardless of their content. This eliminates the injection vector entirely because the database parser never interprets the parameter value as executable SQL.

The fix is minimal and preserves the original method signature and behaviour while eliminating the injection risk. No special libraries are required beyond the standard `System.Data.SqlClient` namespace already in use.
