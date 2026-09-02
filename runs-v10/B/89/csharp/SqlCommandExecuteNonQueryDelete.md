## Verdict

Exploitable. The code directly concatenates untrusted input from HTTP request parameters into a SQL query string passed to `SqlCommand.ExecuteNonQuery()`, enabling SQL injection.

## Source

`AdminCleanupController.DeleteLogs()` receives two untrusted parameters:
- `tenantId`: from the URL route parameter (line 17, `{tenantId}`)
- `before`: from the query string (line 17, `[FromQuery] string before`)

Both are passed to `CleanupRepository.DeleteLogs()` without validation.

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
    const string sql = "DELETE FROM AuditLogs WHERE TenantId = @TenantId AND CreatedAt < @BeforeDate";
    using var command = new SqlCommand(sql, _connection);
    command.Parameters.Add("@TenantId", SqlDbType.NVarChar).Value = tenantId;
    command.Parameters.Add("@BeforeDate", SqlDbType.NVarChar).Value = beforeDate;
    return command.ExecuteNonQuery();
}
```

## Explanation

The vulnerability exists because `tenantId` and `beforeDate` are concatenated directly into the SQL string. An attacker can inject SQL syntax; for example, a malicious `tenantId` value like `' OR '1'='1' --` would transform the query into `DELETE FROM AuditLogs WHERE TenantId = '' OR '1'='1' -- AND ...`, bypassing the WHERE clause and deleting all records.

The fix replaces string concatenation with parameterized queries using `SqlCommand.Parameters.Add()`. Parameters with placeholders (`@TenantId`, `@BeforeDate`) ensure that user input is always treated as data values, never as query structure. The database driver handles escaping and type conversion automatically, preventing SQL injection regardless of the input content.

## Behaviour changes

None. The fixed code preserves the original behavior completely: it accepts the same parameters, executes the same DELETE logic with identical conditions, and returns the same value from `ExecuteNonQuery()` (the number of rows affected). Parameterization is transparent to the caller and does not alter the method's contract.
