## Verdict

Confirmed SQL injection vulnerability. The `actor` parameter from user input (HTTP query string) flows untrusted through the controller to the repository method and is concatenated directly into the SQL query string before execution. An attacker can inject SQL syntax to alter query logic, access unauthorized data, or execute administrative operations.

## Source

User input enters via HTTP query parameter `actor` in `MetricsController.ActorCount([FromQuery] string actor)` at line 17, flows to `AuditMetricRepository.CountEvents(string actor)` at line 14, and is concatenated into the SQL command string at line 17 of `AuditMetricRepository.cs`:

```
command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = '" + actor + "'";
```

The concatenated string is then executed at line 18 via `command.ExecuteScalar()`.

**Exploitation example**: Input `' OR '1'='1' --` produces:
```sql
SELECT COUNT(*) FROM AuditEvents WHERE Actor = '' OR '1'='1' --'
```
This returns the count of all rows regardless of actor value.

## Fix

Replace string concatenation with parameterized queries. Use `SqlCommand.Parameters` to bind the untrusted value separately from the query structure:

```csharp
public int CountEvents(string actor)
{
    using var command = _connection.CreateCommand();
    command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = @actor";
    command.Parameters.Add("@actor", SqlDbType.NVarChar).Value = actor;
    return (int)command.ExecuteScalar();
}
```

The placeholder `@actor` is replaced by the database driver with a parameter marker, and the value of `actor` is passed separately in a way the database driver interprets only as data, never as executable SQL code. This ensures user input cannot alter the query structure.

## Explanation

Parameterized queries (prepared statements) are the primary defence against SQL injection. The query structure is defined first with placeholders (`@actor`), and user-supplied data is bound as a parameter with an explicit type (`SqlDbType.NVarChar`). The database driver ensures the parameter value is always treated as a literal string value, never as part of the SQL syntax. String concatenation provides no such guarantee - any special characters in the input (single quotes, comments, operators) are interpreted as SQL by the database parser and can change the query logic.

The fix preserves the method's contract: it still accepts a string parameter, still returns `int`, and still uses `ExecuteScalar()` to retrieve the count. The only change is how the untrusted value reaches the SQL engine - through parameterization instead of string concatenation.

## Behaviour changes

- Query returns same results for all valid actor names (no change to logic)
- Payloads that previously altered the query (e.g., `' OR '1'='1'`) are now treated as literal strings and return no matches, as intended
- Parameter type is explicitly `SqlDbType.NVarChar` to match the database schema
