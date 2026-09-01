## Verdict

Exploitable. Untrusted input from HTTP route and query parameters flows directly into SQL query string concatenation, allowing SQL injection through special characters or SQL syntax in tenantId or beforeDate values.

## Source

HTTP request to `DELETE /admin/cleanup/tenant/{tenantId}/logs?before={beforeDate}` (AdminCleanupController.DeleteLogs, lines 17-19) receives untrusted tenantId from route and before from query string, both passed unsanitized to CleanupRepository.DeleteLogs.

## Fix

**Vulnerable code (CleanupRepository.cs, lines 14-19):**

```csharp
public int DeleteLogs(string tenantId, string beforeDate)
{
    var sql = "DELETE FROM AuditLogs WHERE TenantId = '" + tenantId + "' AND CreatedAt < '" + beforeDate + "'";
    using var command = new SqlCommand(sql, _connection);
    return command.ExecuteNonQuery();
}
```

**Fixed code:**

```csharp
public int DeleteLogs(string tenantId, string beforeDate)
{
    var sql = "DELETE FROM AuditLogs WHERE TenantId = @tenantId AND CreatedAt < @beforeDate";
    using var command = new SqlCommand(sql, _connection);
    command.Parameters.Add("@tenantId", SqlDbType.NVarChar).Value = tenantId;
    command.Parameters.Add("@beforeDate", SqlDbType.DateTime).Value = beforeDate;
    return command.ExecuteNonQuery();
}
```

## Explanation

The fix replaces string concatenation with parameterized queries. The SQL query now uses placeholders (`@tenantId` and `@beforeDate`) instead of embedding untrusted values directly into the SQL string. The actual parameter values are added to the command's `Parameters` collection with explicit `SqlDbType` declarations, ensuring they are always treated as data values, never as executable SQL code. This prevents SQL injection regardless of what characters or SQL metacharacters appear in the tenantId or beforeDate values.

## Behaviour changes

None. The query executes the same DELETE operation with identical filtering logic. The Parameters collection's `Add` method with explicit SqlDbType declarations replaces string interpolation; the SqlCommand still receives the same connection and executes with the same return value contract (number of rows affected). Exception behavior on database errors is identical.

