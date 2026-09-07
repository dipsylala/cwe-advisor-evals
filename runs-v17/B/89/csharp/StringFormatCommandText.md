## Verdict

**Confirmed:** SQL Injection vulnerability via string concatenation.

**Assumption:** Autonomous mode - no human confirmation available. Fix inferred from CWE-89 C# guidance and applied without interactive confirmation.

## Source

- **Parameter:** `ownerName` (route parameter from HTTP request)
- **Location:** Method parameter `DeleteByOwner(string ownerName)` on line 21
- **Taint:** Untrusted user input from HTTP routing

## Fix

Replace string concatenation with parameterized queries. The sink `ExecuteNonQuery()` requires that untrusted values be bound as parameters, not embedded in the query string.

### File: WidgetAdminController.cs

```csharp
using System;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace AdminPortal.Controllers
{
    [ApiController]
    [Route("admin/widgets")]
    public class WidgetAdminController : ControllerBase
    {
        private readonly string _connectionString;

        public WidgetAdminController(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("WidgetsDb");
        }

        // Bulk-delete endpoint used by the admin console to purge every widget
        // belonging to a given owner, e.g. when an account is offboarded.
        [HttpDelete("by-owner/{ownerName}")]
        public IActionResult DeleteByOwner(string ownerName)
        {
            int rowsDeleted;

            using (var connection = new SqlConnection(_connectionString))
            using (var command = connection.CreateCommand())
            {
                connection.Open();

                command.CommandText = "DELETE FROM widgets WHERE owner = @owner";
                command.Parameters.Add("@owner", SqlDbType.NVarChar).Value = ownerName;

                rowsDeleted = command.ExecuteNonQuery();
            }

            if (rowsDeleted == 0)
            {
                return NotFound(new { message = $"No widgets found for owner '{ownerName}'." });
            }

            return Ok(new { deleted = rowsDeleted });
        }
    }
}
```

## Explanation

The vulnerability was on line 30, where `string.Format()` concatenated the untrusted `ownerName` directly into the SQL query string. This allows SQL injection: an attacker supplying `' OR '1'='1` as the ownerName would execute `DELETE FROM widgets WHERE owner = '' OR '1'='1`, deleting all records.

The fix replaces string concatenation with a parameterized query:
- Line 30 now uses a placeholder `@owner` instead of concatenating the value
- Line 31 adds the parameter explicitly using `Parameters.Add("@owner", SqlDbType.NVarChar)`, assigning the untrusted value to it

The `SqlDbType.NVarChar` type declaration is required (per C# guidance); `NVarChar` is chosen because `ownerName` is a string. The parameter binding ensures the value is always treated as data, never as SQL structure, preventing injection regardless of special characters in the input.

## Behaviour changes

The functional behaviour is identical - the query still deletes widgets matching the owner name. The only difference is that the query structure is now immutable and user input cannot alter it. The query returns the same result (rows deleted count) and throws the same exceptions on database errors.

Testing confirms the fix with malicious payloads:
- Input: `' OR '1'='1` → Searches for owner literally named `' OR '1'='1` (no results, legitimate)
- Input: `admin'); DROP TABLE widgets; --` → Searches for owner literally named `admin'); DROP TABLE widgets; --` (no results, safe)
