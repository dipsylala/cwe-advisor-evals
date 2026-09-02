## Verdict

Confirmed. `SearchByOwner` builds the SQL command text by concatenating the unvalidated `owner` query-string parameter directly into a `SELECT` statement, then executes it with `SqlCommand.ExecuteReader()`. An attacker who controls `owner` controls query structure (e.g. `' OR '1'='1`), giving arbitrary read access to the `Accounts` table.

## Source

`owner`, bound from the query string via `[FromQuery] string owner` on `AccountsController.SearchByOwner` (`RawSqlCommandConcat.cs:19`). No validation or encoding is applied before use.

## Fix

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
            command.Parameters.Add("@owner", SqlDbType.NVarChar, 100).Value = owner;

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

The vulnerable line built the SQL text with string concatenation (`"... WHERE Owner = '" + owner + "'"`), so any quote or SQL keyword in `owner` became part of the query rather than staying data. The fix replaces the literal with a `@owner` placeholder and binds the value through `SqlCommand.Parameters.Add("@owner", SqlDbType.NVarChar, 100).Value = owner`, per the C# guidance's preference for an explicit `SqlDbType` over `AddWithValue()`. The database driver now sends `owner` to SQL Server as a typed parameter value, never as part of the command text, so quote characters or SQL keywords in it cannot alter the query's structure. `Owner` is a value being matched (not a table/column/identifier), so the fix is a straightforward parameter bind - no allowlist is needed here. The 100-character size is an assumption in the absence of a known column definition; it should be aligned to the actual `Owners.Owner` column width, and a size smaller than that would silently truncate rather than error, per the guidance's note on `SqlDbType.NVarChar` sizing.

## Behaviour changes

- The query now matches `Owner` using a bound parameter instead of an interpolated string literal; functionally equivalent exact-match semantics are preserved for legitimate input (no wildcard/LIKE behavior existed before or after).
- A parameter size of `100` (`NVarChar`) is introduced; if the real `Owner` column is wider than 100 characters, values beyond that length will be truncated at the parameter rather than raising an error. This should be verified against the actual schema and adjusted if needed.
- `command.CommandType` remains the default (`Text`), and all other statement behavior (connection handling, reader consumption, response shape) is unchanged.
