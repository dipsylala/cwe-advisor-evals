## Verdict
SQL injection vulnerability confirmed. User-controlled `tenantId` and `beforeDate` parameters are concatenated directly into the SQL query string without escaping or parameterization, allowing arbitrary SQL to be injected.

## Source
`AdminCleanupController.DeleteLogs()` receives `tenantId` from the URL path parameter and `before` from the query string. Both are passed directly to `CleanupRepository.DeleteLogs(tenantId, beforeDate)`, where they are used in string concatenation on line 16.

## Fix
Replace string concatenation with parameterized query parameters:

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

## Explanation
Parameterized queries separate the SQL structure from user input, preventing attackers from injecting SQL syntax. The `SqlCommand.Parameters` collection treats each parameter value as data only, not as executable SQL code. This approach is the standard defense against SQL injection in .NET and works regardless of special characters or SQL keywords in the parameter values.
