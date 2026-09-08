## Verdict
Vulnerable. The `ownerName` parameter is interpolated directly into the SQL query via `string.Format()`, allowing SQL injection.

## Source
Line 30 constructs the SQL command by embedding the untrusted `ownerName` parameter directly into the query string: `string.Format("DELETE FROM widgets WHERE owner = '{0}'", ownerName)`.

## Fix
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

                command.CommandText = "DELETE FROM widgets WHERE owner = @ownerName";
                command.Parameters.AddWithValue("@ownerName", ownerName);

                // SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
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
The vulnerability stems from constructing SQL queries via string formatting with untrusted input. An attacker controlling `ownerName` can inject SQL syntax—for example, passing `admin' OR '1'='1` to alter the query logic.

The fix uses parameterized queries: the SQL string contains a placeholder `@ownerName`, and the actual value is bound separately via `command.Parameters.AddWithValue()`. The SQL parser treats the parameter value as data, not as executable SQL syntax, preventing injection.

This approach is the standard SQL injection defense in .NET: SqlClient's parameter binding ensures the value cannot be interpreted as SQL code, regardless of its content.
