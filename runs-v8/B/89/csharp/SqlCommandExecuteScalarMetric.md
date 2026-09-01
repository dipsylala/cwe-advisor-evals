## Verdict

**Confirmed**: SQL Injection via string concatenation in `SqlCommand.CommandText`.

## Source

The `actor` parameter passed to `CountEvents()` at line 14 originates from the method caller and is untrusted. It is concatenated directly into the SQL query string on line 17 without any parameterization.

Data flow: `actor` parameter → string concatenation on line 17 → `CommandText` assignment → `ExecuteScalar()` sink on line 18.

## Fix

Replace the concatenated query with a parameterized query using `SqlCommand.Parameters.Add()`:

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

The fix replaces string concatenation with parameterized query binding. The `@Actor` placeholder in the SQL string is bound as a separate parameter via `Parameters.Add()`, which treats the `actor` value as data rather than executable SQL syntax. This prevents an attacker from injecting SQL commands through the `actor` parameter. For example, a malicious input like `' OR '1'='1` is now treated as a literal string value rather than SQL logic, blocking the injection vector.

The parameter type is `SqlDbType.NVarChar` (appropriate for string data in SQL Server), and the Value assignment binds the `actor` variable. The `ExecuteScalar()` call now executes a safe parameterized query that is immune to SQL injection.

## Behaviour changes

**Functional changes**: None. The query returns the same result set for all valid inputs.

**Output changes**: None. The return type and value remain identical.

**Error handling**: No change. `ExecuteScalar()` still throws `SqlException` on connection or query errors, with the same exception semantics.

**Side effects**: None. The parameter binding produces no side effects beyond parameterization.
