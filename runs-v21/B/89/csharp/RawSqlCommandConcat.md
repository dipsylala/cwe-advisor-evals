## Verdict

exploitable

## Source

The `owner` parameter from `[FromQuery] string owner` (line 19) receives untrusted user input from the HTTP query string.

## Fix

### File: RawSqlCommandConcat.cs

```csharp
using System;
using System.Data;
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

            string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @owner";
            using var command = new SqlCommand(sql, connection);
            command.Parameters.Add("@owner", SqlDbType.NVarChar).Value = owner;

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

The vulnerability was a classic SQL injection: the untrusted `owner` parameter was concatenated directly into the SQL query string on line 24, allowing an attacker to inject arbitrary SQL syntax. For example, passing `' OR '1'='1` would transform the query to bypass the WHERE clause.

The fix replaces string concatenation with parameterized queries, the primary defence against SQL injection. The SQL query now uses the placeholder `@owner` instead of concatenating the input value, and the parameter is bound separately using `SqlCommand.Parameters.Add()` with an explicit `SqlDbType.NVarChar`. This ensures the database driver treats the `owner` value as data, never as executable SQL structure, regardless of its content. The `using System.Data;` import is required because `SqlDbType` resides in that namespace.

## Behaviour changes

- Added `using System.Data;` import to support `SqlDbType` enum
- Replaced string concatenation with parameterized query placeholder (`@owner`)
- Added explicit parameter binding: `command.Parameters.Add("@owner", SqlDbType.NVarChar).Value = owner;` before `ExecuteReader()`

All other behavior is preserved: the query still returns the same columns, processes the same result set, and returns the same response structure.
