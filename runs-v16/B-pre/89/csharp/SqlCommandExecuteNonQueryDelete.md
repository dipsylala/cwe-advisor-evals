## Verdict

Exploitable SQL injection via string concatenation in `DeleteLogs` method. Untrusted HTTP parameters (`tenantId` and `beforeDate`) are concatenated directly into an SQL query string that is then executed via `SqlCommand.ExecuteNonQuery()`.

## Source

- **Entry point**: `AdminCleanupController.DeleteLogs(string tenantId, [FromQuery] string before)` receives untrusted data from HTTP route parameter and query string
- **Intermediate**: Data flows unchanged to `CleanupRepository.DeleteLogs(string tenantId, string beforeDate)`
- **Vulnerable sink**: Line 18, `command.ExecuteNonQuery()`

The data flow is:
1. HTTP request provides `tenantId` (route) and `before` (query)
2. Controller passes both to repository method
3. Repository concatenates both into SQL string at line 16
4. SqlCommand executes the concatenated string at line 18

Example injection: `tenantId = "'; DROP TABLE AuditLogs; --"` produces `DELETE FROM AuditLogs WHERE TenantId = ''; DROP TABLE AuditLogs; --' AND CreatedAt < ...`, which executes two statements.

## Fix

Replace string concatenation with parameterized query using `SqlCommand.Parameters`:

```csharp
public int DeleteLogs(string tenantId, string beforeDate)
{
    var sql = "DELETE FROM AuditLogs WHERE TenantId = @TenantId AND CreatedAt < @BeforeDate";
    using var command = new SqlCommand(sql, _connection);
    command.Parameters.Add("@TenantId", SqlDbType.NVarChar).Value = tenantId;
    command.Parameters.Add("@BeforeDate", SqlDbType.NVarChar).Value = beforeDate;
    return command.ExecuteNonQuery();
}
```

Key changes:
- SQL query uses parameter placeholders (`@TenantId`, `@BeforeDate`) instead of string concatenation
- Parameters are added explicitly with `SqlDbType` and assigned their values separately
- The database driver ensures parameters are escaped and treated as data, not SQL structure

## Explanation

Parameterized queries separate SQL structure from data: the query template is compiled once with placeholders, and values are bound as data in a separate step. This is enforced by the database driver and cannot be bypassed by SQL metacharacters in the input.

String concatenation in SQL always fails here because the attacker controls the boundary between the literal `'` and the data - adding a quote, comment, or semicolon in the input redefines the query structure. Parameterization prevents this by shifting the boundary enforcement to the driver layer, where quotes are escapes in the wire protocol, not SQL syntax.

`SqlDbType.NVarChar` preserves the string type and allows the database to apply its own datetime parsing for the `CreatedAt < @BeforeDate` comparison; if validation is needed, add input validation as a secondary layer, but never rely on it alone.

## Behaviour changes

- Parameterized queries are slightly faster on repeated execution (query plan cached by statement text alone)
- Parameter binding happens at the driver level, so invalid date formats in `beforeDate` will be caught by SQL Server's implicit conversion or fail the command at execute time, not by C# validation - this is appropriate since the sink determines the acceptable format
- The fix does not change the method signature, return value, or behavior on success
- Error handling remains the same (SqlException on SQL execution failure)
