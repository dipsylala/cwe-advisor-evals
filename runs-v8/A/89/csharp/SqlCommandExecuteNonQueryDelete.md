## Verdict

**CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)**

Confirmed. The SQL query is constructed using string concatenation with unsanitized user inputs, allowing attackers to inject arbitrary SQL commands.

## Source

Line 16 in `CleanupRepository.cs` constructs the SQL command by concatenating user-supplied parameters:

```csharp
var sql = "DELETE FROM AuditLogs WHERE TenantId = '" + tenantId + "' AND CreatedAt < '" + beforeDate + "'";
```

Both `tenantId` and `beforeDate` parameters flow directly into the SQL string without validation or escaping. An attacker controlling either parameter can break out of the quoted string and inject malicious SQL.

## Fix

Replace the vulnerable string concatenation with parameterized queries using `SqlParameter`:

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

Parameterized queries (`SqlParameter`) treat user inputs as data values, not executable SQL code. The database engine receives the SQL structure and the data separately, preventing syntax-based injection attacks. Even if `tenantId` contains characters like `' OR '1'='1`, they are interpreted as literal string values within the parameter, not as SQL operators. This is the standard, vendor-recommended approach for safe SQL execution in .NET applications using `SqlCommand`.
