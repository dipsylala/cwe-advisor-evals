## Verdict

SQL injection vulnerability confirmed. The `actor` parameter is concatenated directly into the SQL command string without parameterization, allowing an attacker to inject arbitrary SQL.

## Source

```csharp
public int CountEvents(string actor)
{
    using var command = _connection.CreateCommand();
    command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = '" + actor + "'";
    return (int)command.ExecuteScalar();
}
```

## Fix

```csharp
public int CountEvents(string actor)
{
    using var command = _connection.CreateCommand();
    command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = @actor";
    command.Parameters.AddWithValue("@actor", actor);
    return (int)command.ExecuteScalar();
}
```

## Explanation

The vulnerability exists because the `actor` parameter is directly interpolated into the SQL string. An attacker can pass a value like `' OR '1'='1` to alter the query logic or extract data.

The fix uses parameterized queries by:
1. Replacing the concatenated value with a placeholder `@actor` in the SQL string
2. Adding a `SqlParameter` via `AddWithValue()` to bind the actual value

The SQL engine treats the parameter value as data only, not as executable SQL code, preventing injection attacks. This is the standard and recommended approach for all SQL command construction in C# with `SqlCommand`.
