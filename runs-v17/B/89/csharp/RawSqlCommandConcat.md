## Verdict

CONFIRMED - The finding is a real SQL injection vulnerability that allows arbitrary SQL command injection through the `owner` query parameter.

## Source

**File:** `RawSqlCommandConcat.cs`  
**Line:** 24  
**Data path:** `owner` parameter (from `[FromQuery]` binding) → concatenated into SQL string → passed to `SqlCommand` → executed via `command.ExecuteReader()` at line 28.

The `owner` query parameter originates from untrusted user input and flows directly into the SQL query string via string concatenation without any sanitization or parameterization.

**Exploitation:** An attacker can supply `' OR '1'='1` or similar payloads to manipulate query logic, bypass authentication, or exfiltrate data.

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

The fix replaces the concatenated SQL query with a parameterized prepared statement. The changes are:

1. **Line 2 (import):** Added `using System.Data;` to provide access to `SqlDbType` enum for explicit parameter typing.

2. **Line 24 (query):** Changed from `"SELECT AccountId, Balance FROM Accounts WHERE Owner = '" + owner + "'"` to `"SELECT AccountId, Balance FROM Accounts WHERE Owner = @owner"` - the `@owner` placeholder is a SQL parameter reference, not string interpolation.

3. **Line 25 (new line):** Added `command.Parameters.Add("@owner", SqlDbType.NVarChar).Value = owner;` - this binds the untrusted `owner` value as a parameter with explicit type `SqlDbType.NVarChar`. The database driver handles escaping and ensures the value is treated as literal data, never as SQL code.

This approach eliminates the injection vector because the parameter value is transmitted to the database separately from the query structure. The database engine never interprets the parameter value as executable SQL, regardless of what special characters or SQL keywords it contains.

## Behaviour changes

**Functional behavior:** Unchanged. The query returns the same results as before; parameterized queries have identical result semantics to concatenated queries.

**Performance:** Negligible to positive. Parameterized queries may benefit from query plan reuse by the database engine for repeated calls with different owner values.

**Security:** The vulnerability is closed. SQL injection via the `owner` parameter is no longer possible because user input cannot alter query structure.

**Explicit breaking changes:** None. All legitimate owner values that worked before will continue to work. The fix is a drop-in replacement.
