## Verdict

Exploitable. CWE-89 (SQL Injection), high confidence.

## Source

`owner`, the `[FromQuery] string owner` parameter of `AccountsController.SearchByOwner` (`RawSqlCommandConcat.cs:19`) - bound directly from the request query string, fully attacker-controlled.

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

The query text at line 24 concatenated the untrusted `owner` value directly into the SQL string, so a value such as `' OR '1'='1` alters the `WHERE` clause and returns every row, and further payloads could reach `UNION`-based extraction or stacked statements depending on the driver. The fix keeps the sink (`SqlCommand.ExecuteReader()`) and its surrounding `using` scoping unchanged, and instead replaces the literal in the SQL text with the `@owner` placeholder, then binds the value with `command.Parameters.Add("@owner", SqlDbType.NVarChar).Value = owner;`. `SqlDbType` requires `using System.Data;`, added alongside the existing `System.Data.SqlClient` using. `Owner` is a variable-length text column, so no explicit `size` argument is supplied - per the loaded C# guidance, a `size` smaller than the value would silently truncate it, and ADO.NET sizes an `NVarChar` parameter from the assigned value when none is given. With this change the driver sends `owner` to SQL Server as a parameter value, never as part of the command text, so it cannot alter the query's structure regardless of its contents.

## Behaviour changes

None. The sink call, its return value (`SqlDataReader`), the `using` disposal scoping, the two columns read (`AccountId`, `Balance`), and the result shape returned via `Ok(results)` are all unchanged. The only differences are the query text (literal replaced by a `@owner` placeholder) and the added parameter binding, both required solely to close the injection; no argument, return value, or error-handling behavior of `ExecuteReader()` was altered.

**Verification**: `dotnet build` (net8.0, SDK `Microsoft.NET.Sdk.Web`, `System.Data.SqlClient` 4.8.6, `Microsoft.AspNetCore.App` framework reference) against a scratch copy of the fixed file - build succeeded, 0 errors, 0 warnings. All symbols used (`SqlDbType`, `Parameters.Add`) resolved against the referenced assemblies; no new package was introduced beyond what the original file already depended on.

**Assumptions**: none - the case is a single self-contained file, the language (C#/ASP.NET Core) was unambiguous from file extension and `using` directives, and the fix follows the loaded `cwe/89/csharp/INDEX.md` guidance directly (parameterized `SqlCommand` via `Parameters.Add` with an explicit `SqlDbType`).
