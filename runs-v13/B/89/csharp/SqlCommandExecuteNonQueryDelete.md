## Verdict

exploitable

## Source

HTTP request parameters: `tenantId` from the route parameter in `AdminCleanupController.DeleteLogs()`, and `beforeDate` from the query string parameter `before`. Both flow unvalidated to `CleanupRepository.DeleteLogs()`.

## Fix

**Vulnerable code:**
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
    command.Parameters.Add("@beforeDate", SqlDbType.NVarChar).Value = beforeDate;
    return command.ExecuteNonQuery();
}
```

## Explanation

The vulnerability occurs because the SQL query is constructed by concatenating untrusted user input directly into the query string. An attacker who controls `tenantId` or `beforeDate` can inject arbitrary SQL, such as `' OR '1'='1`, to bypass the WHERE clause and delete all records in the AuditLogs table, or extract unauthorized data.

The fix replaces string concatenation with parameterized queries using `SqlCommand.Parameters`. Placeholders (`@tenantId` and `@beforeDate`) stand in for the user-supplied values, which are passed to the database engine as separate data parameters rather than as part of the query structure. This ensures the database treats the input as data only, preventing SQL injection regardless of the content.

## Behaviour changes

None. The parameterized query executes the same DELETE logic with identical semantics. The method signature, return value, and side effects (deletion of matching rows) remain unchanged. SqlDbType.NVarChar is the standard type for string parameters in SQL Server; both input strings are treated as Unicode character data exactly as they would be in the original query, but now safely bound as parameters instead of concatenated into the query text.
