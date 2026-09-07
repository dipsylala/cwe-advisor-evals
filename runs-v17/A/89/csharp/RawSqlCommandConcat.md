## Verdict
CONFIRMED

## Source
The `owner` parameter from the HTTP query string is directly concatenated into an SQL query string at line 24 without parameterization, creating a SQL injection vulnerability. The unsanitized input flows into the SqlCommand at line 25 and is executed at line 28.

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
The vulnerability was caused by string concatenation to build the SQL query. The fix uses parameterized queries by:

1. Replacing the concatenated query with a parameterized query using `@Owner` as a placeholder
2. Adding the user input as a parameter to the SqlCommand via `command.Parameters.AddWithValue("@Owner", owner)`

This separates the SQL command structure from the data, preventing the attacker from injecting SQL metacharacters or commands through the `owner` parameter. The SqlClient driver handles proper escaping and quoting of the parameter value.
