## Verdict

SQL injection vulnerability confirmed. The `owner` query parameter is concatenated directly into the SQL command string without parameterization, allowing an attacker to inject arbitrary SQL syntax.

## Source

Line 24 constructs the SQL command by concatenating the untrusted `owner` parameter:
```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = '" + owner + "'";
```

The attacker controls the `owner` input via the query string and can inject SQL metacharacters to manipulate the query logic.

## Fix

Replace string concatenation with parameterized query using `SqlParameter`:

```csharp
[HttpGet("search")]
public IActionResult SearchByOwner([FromQuery] string owner)
{
    using var connection = new SqlConnection(_connectionString);
    connection.Open();

    string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @Owner";
    using var command = new SqlCommand(sql, connection);
    command.Parameters.AddWithValue("@Owner", owner);

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

Parameterized queries treat user input as data, not executable SQL code. The `@Owner` placeholder in the SQL string is filled by the database driver using the parameter value, ensuring any special characters in `owner` are safely escaped and cannot alter the query structure. This eliminates the attack surface for SQL injection while preserving legitimate functionality.
