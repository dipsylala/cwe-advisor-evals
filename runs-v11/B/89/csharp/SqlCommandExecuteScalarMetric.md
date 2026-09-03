## Verdict

Exploitable

## Source

User input from query string parameter `actor` in `MetricsController.cs` line 17, passed unsanitized to `AuditMetricRepository.CountEvents()`.

## Fix

**Vulnerable code:**
```csharp
public int CountEvents(string actor)
{
    using var command = _connection.CreateCommand();
    command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = '" + actor + "'";
    return (int)command.ExecuteScalar();
}
```

**Fixed code:**
```csharp
public int CountEvents(string actor)
{
    using var command = _connection.CreateCommand();
    command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = @Actor";
    command.Parameters.Add("@Actor", SqlDbType.NVarChar).Value = actor;
    return (int)command.ExecuteScalar();
}
```

## Explanation

The fix replaces string concatenation with a parameterized query using `SqlCommand.Parameters`. The placeholder `@Actor` stands in for the user-supplied value in the SQL text, and `command.Parameters.Add()` binds the actual value separately as a parameter. This ensures the input is always treated as data, never as executable SQL code. An attacker passing `' OR '1'='1` will be treated as a literal string to match against the Actor column, not as SQL syntax modification.

## Behaviour changes

None. The parameterized query produces identical results to the original code for all valid inputs, and rejects malicious payloads that the original code would have executed as SQL injection attacks. Return type and error handling remain unchanged.
