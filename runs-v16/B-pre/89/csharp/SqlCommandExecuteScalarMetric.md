## Verdict
exploitable

## Source
Untrusted HTTP query string input flows directly to SQL execution:

**Data path:**
1. HTTP GET parameter `actor` enters `MetricsController.ActorCount([FromQuery] string actor)` at line 17 of MetricsController.cs
2. Passed to `AuditMetricRepository.CountEvents(actor ?? "")` at line 19 of MetricsController.cs
3. AuditMetricRepository.CountEvents() receives the untrusted `actor` parameter
4. String concatenation at line 17 of AuditMetricRepository.cs: `command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = '" + actor + "'"`
5. Executed at line 18: `command.ExecuteScalar()`

**Sink:** `SqlCommand.ExecuteScalar()` at line 18 of AuditMetricRepository.cs

## Fix

**Vulnerable code (AuditMetricRepository.cs, lines 14–19):**
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
    command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = @actor";
    command.Parameters.Add("@actor", SqlDbType.VarChar).Value = actor;
    return (int)command.ExecuteScalar();
}
```

Note: Ensure `using System.Data;` is present in the file's using statements, or use the fully qualified name `System.Data.SqlDbType`.

## Explanation
String concatenation with untrusted input is replaced with parameterized query execution. The `actor` value is now bound as a parameter via `SqlCommand.Parameters.Add()` with an explicit `SqlDbType`, which ensures it is treated as data, not as executable SQL code. The parameter value is always escaped safely by the SQL Server driver; SQL injection is impossible because the query structure is fixed and parameters cannot alter it. An attacker-supplied payload like `' OR '1'='1` becomes a literal string value to match against the Actor column, not SQL syntax.

## Behaviour changes
None. The query returns the same result (an integer count of matching audit events), the method signature is unchanged, and the ExecuteScalar() call executes and returns data identically. The sole functional difference is resilience to injection—the actor value is always interpreted as a string literal, never as SQL code.
