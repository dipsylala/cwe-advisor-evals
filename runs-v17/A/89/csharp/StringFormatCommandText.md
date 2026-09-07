## Verdict
CONFIRMED. SQL Injection vulnerability via unparameterized string formatting of user input into SQL command text.

## Source
Line 30 constructs the SQL DELETE command by directly interpolating the `ownerName` parameter into a string template using `string.Format()`, without parameterization. An attacker controlling `ownerName` can inject arbitrary SQL syntax (e.g., `' OR '1'='1` or `'; DROP TABLE widgets; --`).

Line 33 executes this malformed command text, allowing the attacker's injected SQL to be parsed and executed by the database.

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

                command.CommandText = "DELETE FROM widgets WHERE owner = @owner";
                command.Parameters.AddWithValue("@owner", ownerName);

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
The fix replaces string formatting with parameterized query syntax. The placeholder `@owner` in the command text is bound to the `ownerName` value via `SqlParameter`, which is sent to the database separately from the SQL command structure. This ensures the database engine treats the parameter as a literal value, not executable SQL syntax, preventing injection.

The `AddWithValue()` method automatically infers the SQL type from the .NET value type (string becomes `NVARCHAR`). Any special characters in the parameter value—quotes, semicolons, SQL keywords—are safely escaped by the database driver and cannot alter the command's meaning.
