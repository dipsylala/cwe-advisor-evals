## Verdict

Confirmed. `SearchByOwner` builds the SQL command text by concatenating the untrusted `owner` query-string parameter directly into the query string, then executes it. An attacker-controlled `owner` value can close the string literal and inject arbitrary SQL, altering the query's logic (e.g. `' OR '1'='1`) or chaining additional statements/functions depending on driver behavior.

## Source

`owner` — bound from the incoming HTTP request via `[FromQuery] string owner` on `SearchByOwner` (line 19). This value is fully attacker-controlled.

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
            command.Parameters.Add("@Owner", SqlDbType.NVarChar, 256).Value = owner ?? (object)DBNull.Value;

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

(Add `using System.Data;` for `SqlDbType`, or omit the explicit type/size and just use `command.Parameters.AddWithValue("@Owner", owner ?? (object)DBNull.Value);` if the `Owner` column's exact type/length isn't known.)

## Explanation

The vulnerable line built the query as `"SELECT AccountId, Balance FROM Accounts WHERE Owner = '" + owner + "'"`. Because `owner` is spliced directly into the string, any single quote or SQL syntax it contains becomes part of the command that `ExecuteReader()` executes verbatim — there is no boundary between code and data.

The fix replaces the concatenated literal with a parameter placeholder (`@Owner`) in a `const` SQL string, and supplies the actual value through `SqlCommand.Parameters`. `SqlClient` sends the query text and the parameter value to SQL Server separately: the driver never re-parses `owner`'s contents as SQL syntax, so quotes, comments, or statement terminators inside it are treated purely as literal data for the comparison. This closes the injection regardless of what characters `owner` contains, and it also lets SQL Server cache/reuse the query plan since the SQL text itself no longer varies per request. Using `DBNull.Value` for a null `owner` avoids a `NullReferenceException`/type-conversion issue when the parameter's value would otherwise be `null` and preserves the original query's implicit behavior for a missing filter value.
