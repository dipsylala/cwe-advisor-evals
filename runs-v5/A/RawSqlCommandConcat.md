## Verdict

Confirmed. `SearchByOwner` builds a SQL query by directly concatenating the untrusted `owner` query-string parameter into the command text, then executes it with `SqlCommand.ExecuteReader()`. An attacker who controls `owner` controls part of the SQL statement itself (classic SQL injection), for example supplying `' OR '1'='1` to bypass the intended filter, or a value containing `'; DROP TABLE Accounts--` to attempt destructive statements, or boolean/time-based payloads to exfiltrate data from other tables via `UNION SELECT`.

## Source

`[FromQuery] string owner` parameter on `SearchByOwner` (`RawSqlCommandConcat.cs`, line 19) — attacker-controlled HTTP query-string input, flowing unmodified into the SQL string built on line 24 and executed on line 28.

## Fix

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

            const string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @Owner";
            using var command = new SqlCommand(sql, connection);
            command.Parameters.Add("@Owner", SqlDbType.NVarChar, 256).Value = owner;

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

(Add `using System.Data;` for the `SqlDbType` enum, or reference it fully qualified.)

## Explanation

The root cause is that the query text and the user-supplied value are combined into a single string before the database ever sees them, so the database cannot distinguish "data" from "SQL syntax" — any quote character in `owner` closes the intended string literal and lets the attacker append arbitrary SQL.

The fix replaces string concatenation with a parameterized query: the SQL text now contains a placeholder (`@Owner`) instead of the literal value, and the value is supplied separately via `SqlCommand.Parameters.Add(...).Value`. `SqlClient` sends the command text and the parameter value to SQL Server as distinct channels, so the driver/server always treats `owner` as a literal data value for comparison — it is never parsed as part of the SQL grammar, regardless of what characters it contains. This closes the injection at the mechanism level rather than relying on escaping or blocklisting special characters, which is fragile and easy to bypass (encoding tricks, forgetting a character class, etc.).

Explicitly typing and sizing the parameter (`SqlDbType.NVarChar, 256`) also avoids implicit conversion issues and gives a defined upper bound on the value length; adjust the size/type to match the actual `Owner` column definition. No other behavior of the endpoint changes — the query still filters `Accounts` by the same `Owner` value, it is just passed safely.

To verify: submit a normal owner name and confirm results are unchanged; then submit a value such as `' OR '1'='1` or `x'; DROP TABLE Accounts--` and confirm the query returns zero rows (treated as a literal string with no matching owner) rather than returning all rows or causing an error/schema change — demonstrating the input can no longer alter query structure.
