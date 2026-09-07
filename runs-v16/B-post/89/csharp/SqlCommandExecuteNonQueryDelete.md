## Verdict

**CONFIRMED.** The `DeleteLogs` method constructs an SQL query by concatenating untrusted string parameters (`tenantId` and `beforeDate`) directly into the query string on line 16, then executes it with `SqlCommand.ExecuteNonQuery()` on line 18. This allows SQL injection attacks where an attacker-supplied `tenantId` or `beforeDate` value can inject arbitrary SQL code. For example, `tenantId = "' OR '1'='1"` would alter query logic to delete all records regardless of tenant.

## Source

The vulnerability lies in lines 14-18 of `CleanupRepository.cs`:

```csharp
public int DeleteLogs(string tenantId, string beforeDate)
{
    var sql = "DELETE FROM AuditLogs WHERE TenantId = '" + tenantId + "' AND CreatedAt < '" + beforeDate + "'";
    using var command = new SqlCommand(sql, _connection);
    return command.ExecuteNonQuery();
}
```

The data path flows from the method parameters (`tenantId`, `beforeDate`) directly into string concatenation, then into `SqlCommand` execution. Both parameters are untrusted external input without any parameterization.

## Fix

Replace string concatenation with parameterized queries using `SqlCommand.Parameters`:

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

Key changes:
1. Replace the concatenated values with placeholder parameters (`@tenantId`, `@beforeDate`)
2. Use `command.Parameters.Add()` with an explicit `SqlDbType` to bind each parameter
3. Assign the untrusted value to the parameter's `.Value` property after adding it
4. Pass the value as a separate parameter, not embedded in the query string

## Explanation

Parameterized queries enforce a strict separation between SQL code structure and data values. The database driver parses the query template first, then substitutes the parameter values as pure data without re-parsing. This prevents the database from interpreting special characters in the parameter values (such as `'`, `--`, or `; DROP TABLE`) as SQL syntax. 

The fix uses the SQL Server parameter prefix `@` (required by `SqlCommand`), declares each parameter's type explicitly with `SqlDbType.NVarChar` for string values, and binds the untrusted input as data only, never as part of the query structure. The database always treats the bound values as literal data regardless of their content.

If the `beforeDate` parameter is actually a `DateTime` type at the call site, use `SqlDbType.DateTime` instead, though `NVarChar` with an ISO 8601 string is also safe and avoids type mismatch errors.

## Behaviour changes

- **Query execution:** Functionally identical. The parameterized query produces the same results as the concatenated version for legitimate inputs.
- **Injection prevention:** Malicious inputs like `' OR '1'='1` are now treated as literal string data and will not alter the query logic.
- **Performance:** Parameterized queries can be cached by the database driver and server, potentially improving performance for repeated deletions.
- **Type safety:** Explicitly declaring `SqlDbType` catches type mismatches earlier and prevents implicit type coercion issues.
