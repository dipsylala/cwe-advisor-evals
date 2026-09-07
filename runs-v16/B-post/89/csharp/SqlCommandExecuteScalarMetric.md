## Verdict

Valid SQL Injection vulnerability. The `actor` parameter is untrusted input concatenated directly into the SQL query string at line 17, allowing attackers to inject SQL fragments that modify query logic (e.g., `' OR '1'='1`).

## Source

The `actor` string parameter flows from the method entry point (line 14) into SQL query construction via string concatenation (line 17), then directly to `ExecuteScalar()` execution (line 18). The parameter is never validated or parameterized.

## Fix

Replace string concatenation with `SqlCommand.Parameters` to parameterize the query:

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

The fix replaces the concatenated query string with a parameterized query using `SqlCommand.Parameters`. The `@actor` placeholder is a parameter marker, and the actual value is bound separately via `Parameters.Add()` with an explicit `SqlDbType.NVarChar` type. This ensures the input is always treated as data, not executable SQL code. The database driver handles escaping and prevents the attacker-supplied value from altering query structure, even if it contains SQL syntax characters like quotes or `OR` keywords.

## Behaviour changes

- Query construction: Changed from string concatenation to placeholder-based parameterization
- Parameter binding: The `actor` value is now passed as a `SqlParameter` object with explicit type information rather than embedded in the query text
- Execution: `ExecuteScalar()` executes the same underlying SQL logic but with the parameter safely bound
- No change to return value or caller behavior; the method still returns an `int` count value
