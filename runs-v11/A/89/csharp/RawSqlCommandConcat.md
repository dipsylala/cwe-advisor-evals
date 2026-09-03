## Verdict
Real vulnerability. SQL injection via unsanitized query parameter concatenation.

## Source
Line 24 constructs SQL by string concatenation with user input `owner`:
```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = '" + owner + "'";
```

An attacker supplying `' OR '1'='1` as the owner parameter bypasses the WHERE clause entirely and returns all accounts.

## Fix
Replace string concatenation with parameterized queries using `SqlParameter`:

```csharp
[HttpGet("search")]
public IActionResult SearchByOwner([FromQuery] string owner)
{
    using var connection = new SqlConnection(_connectionString);
    connection.Open();

    string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @Owner";
    using var command = new SqlCommand(sql, connection);
    command.Parameters.AddWithValue("@Owner", owner ?? "");

    using var reader = command.ExecuteReader();

    var results = new System.Collections.Generic.List<object>();
    while (reader.Read())
    {
        results.Add(new { AccountId = reader.GetInt32(0), Balance = reader.GetDecimal(1) });
    }

    return Ok(results);
}
```

The `@Owner` placeholder is bound to the `owner` parameter via `AddWithValue()`. SQL Server treats the parameter value as a literal, never as executable SQL code.

## Explanation
Parameterized queries separate the SQL command structure from its data. The database driver handles escaping automatically, making injection impossible because user input cannot alter the query's syntactic structure.

Key changes:
- Replace `WHERE Owner = '` + owner + `'` with `WHERE Owner = @Owner` placeholder syntax
- Use `SqlParameter` (via `AddWithValue()`) to bind the user input safely
- The parameter is transmitted to SQL Server separately from the command text, not concatenated

This is the primary defence against SQL injection in C# and .NET Framework.
