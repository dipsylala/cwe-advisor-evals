## Verdict
Confirmed SQL injection vulnerability.

## Source
`MetricsController.ActorCount()` receives an untrusted `actor` parameter from a query string (line 17 of MetricsController.cs) and passes it directly to `AuditMetricRepository.CountEvents()` without validation.

## Fix
Replace string concatenation with parameterized queries using `SqlParameter`:

```csharp
public int CountEvents(string actor)
{
    using var command = _connection.CreateCommand();
    command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = @actor";
    command.Parameters.AddWithValue("@actor", actor);
    return (int)command.ExecuteScalar();
}
```

The `@actor` placeholder in the SQL command is replaced with a `SqlParameter` object. The database driver handles escaping and parsing the parameter value separately from the SQL syntax, preventing the attacker-controlled input from being interpreted as SQL code.

## Explanation
The original code concatenates the `actor` variable directly into the SQL string. An attacker who controls the `actor` parameter can inject SQL syntax — for example, passing `' OR '1'='1` would transform the query into `SELECT COUNT(*) FROM AuditEvents WHERE Actor = '' OR '1'='1'`, returning a count of all rows instead of filtering by actor.

Parameterized queries solve this by separating the SQL command structure from the data values. The command text defines the structure (with placeholders like `@actor`), and parameters provide the values. The database driver ensures parameter values are treated as data, not as executable SQL syntax, regardless of what special characters they contain.
