## Verdict
Vulnerable to SQL injection.

## Source
The `actor` parameter is concatenated directly into the SQL command string without sanitization or parameterization. An attacker can inject SQL metacharacters to alter query logic.

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
Replace string concatenation with parameterized query syntax. Use the `@actor` placeholder in the SQL command and add the value as a parameter via `SqlCommand.Parameters.AddWithValue()`. This separates SQL structure from data, ensuring user input is treated as a literal value and cannot alter the query's logic. Parameterized queries are the primary defense against SQL injection in C# when using `System.Data.SqlClient`.
