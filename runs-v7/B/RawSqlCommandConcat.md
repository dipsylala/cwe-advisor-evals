## Verdict

**Confirmed CWE-89 SQL Injection**. The `owner` query parameter is concatenated directly into the SQL query string without parameterization, allowing attackers to inject arbitrary SQL commands (e.g., `' OR '1'='1`).

## Source

HTTP query parameter `owner` (line 19, `[FromQuery] string owner`) flows untrusted into line 24 where it is concatenated into the SQL query string.

## Fix

Replace string concatenation with a parameterized query using `SqlCommand.Parameters`:

```csharp
[HttpGet("search")]
public IActionResult SearchByOwner([FromQuery] string owner)
{
    using var connection = new SqlConnection(_connectionString);
    connection.Open();

    string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @Owner";
    using var command = new SqlCommand(sql, connection);
    command.Parameters.Add("@Owner", SqlDbType.NVarChar).Value = owner;

    using var reader = command.ExecuteReader();

    var results = new System.Collections.Generic.List<object>();
    while (reader.Read())
    {
        results.Add(new { AccountId = reader.GetInt32(0), Balance = reader.GetDecimal(1) });
    }

    return Ok(results);
}
```

## Explanation

The vulnerable code builds SQL by string concatenation, treating the `owner` parameter as query syntax. The fix uses a parameterized query where `@Owner` is a placeholder and the untrusted value is bound via `Parameters.Add()` with an explicit `SqlDbType.NVarChar`. This ensures the database driver treats `owner` as data only, never as executable SQL. The query structure is now fixed and immutable, preventing injection regardless of input content.

## Behaviour changes

No functional changes. The query returns the same result set, the ExecuteReader call contract is unchanged (return type and exception handling are identical), and the while loop iterating over results continues to work. The only change is that malicious SQL fragments are now treated as literal string values rather than query operators.
