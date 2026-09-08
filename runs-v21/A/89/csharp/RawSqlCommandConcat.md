## Verdict

CWE-89 SQL injection confirmed. The `owner` query parameter is concatenated directly into a SQL string without parameterization, allowing an attacker to inject arbitrary SQL commands.

## Source

Line 24 concatenates unsanitized user input into the SQL string:
```
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = '" + owner + "'";
```

The `owner` parameter originates from user input (`[FromQuery] string owner` on line 19) and flows directly into the SQL command text without sanitization or parameterization.

## Fix

### File: RawSqlCommandConcat.cs

```csharp
using System;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountsController : ControllerBase
    {
        private readonly string _connectionString;

        public AccountsController(string connectionString)
        {
            _connectionString = connectionString;
        }

        [HttpGet("search")]
        public IActionResult SearchByOwner([FromQuery] string owner)
        {
            using var connection = new SqlConnection(_connectionString);
            connection.Open();

            string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @Owner";
            using var command = new SqlCommand(sql, connection);
            command.Parameters.AddWithValue("@Owner", owner);

            // SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
            using var reader = command.ExecuteReader();

            var results = new System.Collections.Generic.List<object>();
            while (reader.Read())
            {
                results.Add(new { AccountId = reader.GetInt32(0), Balance = reader.GetDecimal(1) });
            }

            return Ok(results);
        }
    }
}
```

## Explanation

The vulnerability is remediated by replacing string concatenation with parameterized queries. Instead of building the SQL string with string concatenation (`"... WHERE Owner = '" + owner + "'"`), the fix uses a parameter placeholder (`@Owner`) in the SQL string and adds the user input as a parameter via `command.Parameters.AddWithValue("@Owner", owner)`.

Parameterized queries separate the SQL code structure from user-supplied data, preventing the database from interpreting user input as SQL commands. The database driver handles proper escaping and ensures the value is treated as data, not executable SQL.

This is the standard defense against SQL injection in C# and applies to any `SqlCommand` usage regardless of input source. The attacker cannot inject SQL syntax via the parameter value because the database treats it as a literal string to be matched.
