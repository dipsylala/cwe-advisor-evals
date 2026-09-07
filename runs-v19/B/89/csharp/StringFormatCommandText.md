## Verdict

**Confirmed SQL Injection vulnerability.** Exploitable: attacker-controlled `ownerName` parameter is concatenated directly into the SQL query via `string.Format`, allowing arbitrary SQL injection (e.g., `ownerName = "' OR '1'='1"` rewrites the WHERE clause).

## Source

**File:** WidgetAdminController.cs  
**Line:** 30 (query construction via concatenation)  
**Sink:** Line 33 (ExecuteNonQuery execution)

The route parameter `ownerName` (line 21) flows untrusted from the HTTP request into SQL query construction on line 30:
```
command.CommandText = string.Format("DELETE FROM widgets WHERE owner = '{0}'", ownerName);
```

Then executed on line 33:
```
rowsDeleted = command.ExecuteNonQuery();
```

## Fix

Replace string concatenation with parameterized queries. The SqlCommand.Parameters API ensures user input is always treated as data, never as query structure.

### File: WidgetAdminController.cs

```csharp
using System;
using System.Data;
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

                command.CommandText = "DELETE FROM widgets WHERE owner = @ownerName";
                command.Parameters.Add("@ownerName", SqlDbType.NVarChar).Value = ownerName;

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

The fix replaces the vulnerable `string.Format()` concatenation with a parameterized query using `SqlCommand.Parameters.Add()`. The SQL query is now a static template where `@ownerName` is a placeholder for the parameter, and the untrusted `ownerName` value is passed separately via the Parameters collection. The SQL engine treats the parameter value as pure data, not as executable SQL, preventing injection attacks.

Added import: `using System.Data;` to access `SqlDbType`.

The fix preserves the original contract: `ExecuteNonQuery()` still returns the number of rows deleted, error handling remains unchanged, and the response to the caller is identical.

## Behaviour changes

- **Parameter binding:** User input is now bound as a SQL parameter rather than interpolated into the query string.
- **Query structure:** The query template is now static and never mutated by user input.
- **No functional change:** The DELETE operation, return value, and error semantics are identical to the original code.
