## Verdict

**CWE-89: SQL Injection Confirmed**

The `owner` parameter from the HTTP query string is directly concatenated into the SQL command without parameterization, allowing attackers to inject arbitrary SQL code.

## Source

```csharp
[HttpGet("search")]
public IActionResult SearchByOwner([FromQuery] string owner)
{
    using var connection = new SqlConnection(_connectionString);
    connection.Open();

    string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = '" + owner + "'";
    using var command = new SqlCommand(sql, connection);

    using var reader = command.ExecuteReader();
    // ... rest of method
}
```

The vulnerability exists at line 24, where concatenation mixes SQL code with untrusted data. An attacker supplying `owner = ' OR '1'='1` would alter the query logic entirely.

## Fix

```csharp
[HttpGet("search")]
public IActionResult SearchByOwner([FromQuery] string owner)
{
    using var connection = new SqlConnection(_connectionString);
    connection.Open();

    string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @owner";
    using var command = new SqlCommand(sql, connection);
    command.Parameters.AddWithValue("@owner", owner);

    using var reader = command.ExecuteReader();
    // ... rest of method
}
```

Replace string concatenation with a parameterized query using `@owner` placeholder and `SqlParameter`. The value is transmitted to the database engine separately from the SQL template, preventing injection.

## Explanation

Parameterized queries enforce a hard boundary between SQL structure and data. The database driver sends the template and parameter values as separate protocol messages, so the database parser never interprets the parameter's content as SQL syntax. This is the standard mitigation for SQL injection across all major database libraries in C#: EntityFramework's `.FromSql()` with parameters, Dapper's named parameters, or raw `SqlCommand` with `Parameters.AddWithValue()`. String concatenation, string interpolation, and `$` strings all suffer the same vulnerability and must be replaced.
