## Verdict

Real issue. SQL Injection via string concatenation.

## Source

Route parameter `tenantId` (from `[HttpDelete("tenant/{tenantId}/logs")]`) and query parameter `before` (from `[FromQuery] string before`) in `AdminCleanupController`, passed to `DeleteLogs()` in `CleanupRepository`.

## Fix

Replace string concatenation with parameterized query:

```csharp
public int DeleteLogs(string tenantId, string beforeDate)
{
    var sql = "DELETE FROM AuditLogs WHERE TenantId = @TenantId AND CreatedAt < @BeforeDate";
    using var command = new SqlCommand(sql, _connection);
    command.Parameters.Add("@TenantId", SqlDbType.NVarChar).Value = tenantId;
    command.Parameters.Add("@BeforeDate", SqlDbType.DateTime).Value = beforeDate;
    return command.ExecuteNonQuery();
}
```

## Explanation

The vulnerability occurs because untrusted input (`tenantId` and `beforeDate`) is concatenated directly into the SQL query string. An attacker can inject SQL by providing a value like `' OR '1'='1` for `tenantId`, which modifies the query logic and allows unauthorized data deletion.

The fix uses parameterized queries with `@TenantId` and `@BeforeDate` placeholders. Values are bound separately via `Parameters.Add()` with explicit `SqlDbType` specification (NVarChar for string identifiers, DateTime for date values). This ensures user input is always treated as data, never as SQL structure, regardless of special characters present.

## Behaviour changes

None. The parameterized query produces identical results to the original code for valid inputs. Injection attempts that previously succeeded now fail safely—the malicious input is treated as a literal string value, not query syntax. The method's return type and exception behaviour remain unchanged.
