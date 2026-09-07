## Verdict

Exploitable. An attacker can inject SQL through the `owner` query parameter by supplying `' OR '1'='1` or similar payloads, bypassing the WHERE clause logic and accessing unauthorized data.

## Source

**Location:** E:/Github/cwe-advisor/evals/cases/89/csharp/RawSqlCommandConcat/RawSqlCommandConcat.cs:19,24,28

**Source:** Line 19, `[FromQuery] string owner` - untrusted HTTP query string parameter

**Sink:** Line 28, `command.ExecuteReader()` - executes the SQL command

**Data Flow:** Line 24 concatenates `owner` directly into the SQL string without parameterization:
```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = '" + owner + "'";
```

An attacker can inject SQL via `owner = ' OR '1'='1`, producing:
```sql
SELECT AccountId, Balance FROM Accounts WHERE Owner = '' OR '1'='1'
```
This returns all accounts, bypassing the intended filter.

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

            string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @Owner";
            using var command = new SqlCommand(sql, connection);
            command.Parameters.Add("@Owner", SqlDbType.NVarChar).Value = owner;

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

The fix replaces string concatenation with parameterized query execution. Line 24 changes from building SQL by concatenating user input (`+ owner +`) to using a placeholder (`@Owner`), and line 25 adds the parameter binding using `SqlCommand.Parameters.Add("@Owner", SqlDbType.NVarChar).Value = owner`. The `System.Data` namespace is added to provide `SqlDbType`. With parameterization, the database driver treats the `owner` value exclusively as data, never as SQL code, preventing injection regardless of its content. The placeholder `@Owner` is a structural part of the query that cannot be altered by the parameter value.

## Behaviour changes

1. **Added `using System.Data;`** - Required for `SqlDbType` enum; no functional change, purely to resolve the type name.
2. **Line 24: SQL string changed from concatenation to parameterized format** - `WHERE Owner = '" + owner + "'"` becomes `WHERE Owner = @Owner`. This is the core fix; the query structure no longer depends on the parameter value.
3. **Line 25: Added parameter binding** - `command.Parameters.Add("@Owner", SqlDbType.NVarChar).Value = owner;`. This passes the owner value to the query engine as data, not as SQL syntax. The parameter is declared with `SqlDbType.NVarChar` to match the string type of the database column and ensure proper handling.
4. **Sink contract preserved** - `ExecuteReader()` still returns a `SqlDataReader` and the code reads results identically. Connection lifecycle, error handling, and return type are unchanged.

No unrelated changes or scope creep.
