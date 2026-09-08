## Verdict

Exploitable. The `ownerName` route parameter is concatenated directly into an SQL query using `string.Format()` without parameterization, allowing SQL injection.

## Source

**Source:** The `ownerName` route parameter (line 21) from the DELETE endpoint URI path.

**Sink:** `command.ExecuteNonQuery()` at line 33.

**Data Flow:** 
1. User-supplied `ownerName` from the route parameter reaches `DeleteByOwner(string ownerName)` 
2. Line 30 embeds it directly into SQL via `string.Format("DELETE FROM widgets WHERE owner = '{0}'", ownerName)`
3. The constructed command text is executed at line 33 with `ExecuteNonQuery()`

**Exploitation:** An attacker can inject SQL by passing a crafted owner name such as `' OR '1'='1`, which transforms the query to `DELETE FROM widgets WHERE owner = '' OR '1'='1'`, deleting all widgets regardless of owner.

## Fix

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

The vulnerability was eliminated by replacing string concatenation with parameterized query execution. The fix converts the vulnerable `string.Format()` construction to a static SQL query with a parameter placeholder (`@owner`), and binds the user-supplied `ownerName` value separately via `SqlCommand.Parameters.Add()` with an explicit type (`SqlDbType.NVarChar`). This ensures the database driver treats the bound value as data, not as executable SQL structure. The parameter is passed to the SQL engine as a distinct data value, preventing any injected SQL metacharacters from being interpreted as query logic. Added `using System.Data;` to access the `SqlDbType` enum, which is required for explicit parameter typing.

## Behaviour changes

**Added import:** `using System.Data;` — required to access `SqlDbType` enum; no functional change to the application.

**Query construction (lines 31–32):**
- Original: Built query string via `string.Format()`, query contained embedded untrusted data
- Fixed: Static query text with parameterized placeholder; untrusted data bound separately through `Parameters.Add()`

**Sink behavior:** `ExecuteNonQuery()` behavior is unchanged—it still returns the count of affected rows and throws exceptions on SQL errors. The parameterization is transparent to the caller; only the mechanism of value passing is safer.

**Error handling:** Unchanged. Invalid SQL syntax or constraint violations still throw `SqlException` as before.

No breaking changes. The endpoint behavior is identical: it deletes widgets matching the given owner name and returns the row count.
