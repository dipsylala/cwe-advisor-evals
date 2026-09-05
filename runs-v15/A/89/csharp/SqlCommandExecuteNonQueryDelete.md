## Verdict
CONFIRMED. SQL injection vulnerability via string concatenation in SQL command.

## Source
Line 16 concatenates user-supplied `tenantId` and `beforeDate` directly into the SQL query without parameterization, allowing attackers to inject arbitrary SQL commands.

```csharp
var sql = "DELETE FROM AuditLogs WHERE TenantId = '" + tenantId + "' AND CreatedAt < '" + beforeDate + "'";
using var command = new SqlCommand(sql, _connection);
return command.ExecuteNonQuery();
```

## Fix
Use `SqlParameter` to pass user input safely, separating SQL structure from data:

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
The original code builds SQL by concatenating strings, which allows attackers to inject SQL syntax through the `tenantId` or `beforeDate` parameters. For example, if `tenantId` is `' OR '1'='1`, the query becomes `DELETE FROM AuditLogs WHERE TenantId = '' OR '1'='1' AND ...`, deleting all rows regardless of the condition.

Parameterized queries separate SQL structure from data: the query template is fixed (`@TenantId` and `@BeforeDate` are placeholders), and parameters are bound separately through `AddWithValue()`. The database driver ensures parameter values are never interpreted as SQL syntax, eliminating injection.
