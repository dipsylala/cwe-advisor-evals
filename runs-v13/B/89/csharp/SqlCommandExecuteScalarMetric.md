## Verdict

Exploitable. The `actor` query parameter flows from user input in `MetricsController.ActorCount` through `AuditMetricRepository.CountEvents` and is concatenated directly into a SQL query string without any validation or parameterization before execution.

## Source

User-supplied `actor` query parameter from `MetricsController.ActorCount` ([FromQuery] string actor) flows to `AuditMetricRepository.CountEvents(string actor)` at line 14 of AuditMetricRepository.cs.

## Fix

**Vulnerable code (AuditMetricRepository.cs, lines 14-19):**

```csharp
public int CountEvents(string actor)
{
    using var command = _connection.CreateCommand();
    command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = '" + actor + "'"; // SQL injection: actor concatenated directly
    return (int)command.ExecuteScalar();
}
```

**Fixed code:**

```csharp
public int CountEvents(string actor)
{
    using var command = _connection.CreateCommand();
    command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = @actor";
    command.Parameters.Add("@actor", SqlDbType.NVarChar).Value = actor;
    return (int)command.ExecuteScalar();
}
```

## Explanation

The fix replaces string concatenation with a parameterized query. Instead of building the SQL string by concatenating the untrusted `actor` value, a placeholder `@actor` is used in the query, and the actual value is passed separately via `command.Parameters.Add()`. This ensures the database treats the `actor` value strictly as data, not as executable SQL code. An attacker can no longer break out of the string literal to inject SQL logic, because the value is bound as a parameter with type `SqlDbType.NVarChar`, preventing any metacharacter interpretation by the SQL engine.

## Behaviour changes

None. The parameterized query produces identical results to the original query when given the same legitimate input. The `ExecuteScalar()` call returns the same integer count, and the return value remains unchanged. The only operational difference is that SQL injection payloads are now neutralized because they are treated as string literals rather than SQL syntax.
