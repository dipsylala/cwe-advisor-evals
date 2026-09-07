## Verdict

**Confirmed SQL injection via string concatenation in parameterized query context.**

The code concatenates untrusted user input (`actor`) directly into a SQL command string instead of using parameterized queries, allowing an attacker to inject arbitrary SQL.

## Source

**File:** `AuditMetricRepository.cs`, line 18

**Vulnerable method:**
```csharp
public int CountEvents(string actor)
{
    using var command = _connection.CreateCommand();
    command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = '" + actor + "'";
    return (int)command.ExecuteScalar();
}
```

**Call chain:** User-controlled query parameter from `MetricsController.ActorCount()` flows through `AuditMetricRepository.CountEvents(actor)` to direct SQL concatenation.

## Fix

Replace string concatenation with `SqlParameter`:

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

String concatenation (`"... WHERE Actor = '" + actor + "'"`) allows an attacker to inject SQL syntax. For example, if `actor` is `' OR '1'='1`, the query becomes `SELECT COUNT(*) FROM AuditEvents WHERE Actor = '' OR '1'='1'`, which always matches all rows.

Parameterized queries separate SQL syntax from data: the `@actor` placeholder marks a data position, and `AddWithValue()` binds the user input as data only—the database driver ensures the value cannot be interpreted as SQL syntax. This is the standard defense for SQL injection in C# when using `SqlClient` (now `Microsoft.Data.SqlClient`).
