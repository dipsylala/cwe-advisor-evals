## Verdict

Confirmed. `DeleteByOwner` builds the SQL command text with `string.Format` directly from the unvalidated route parameter `ownerName`, then executes it with `command.ExecuteNonQuery()`. An attacker who controls the `{ownerName}` segment of the URL can close the quoted string literal and inject arbitrary SQL (e.g. a stacked statement or a tautology that deletes every row), so this is exploitable SQL injection.

## Source

`ownerName`, the `[HttpDelete("by-owner/{ownerName}")]` route parameter to `DeleteByOwner`, in `WidgetAdminController.cs` line 21. It flows unmodified into the `string.Format` call on line 30, which builds `command.CommandText`, and reaches the sink at line 33 (`command.ExecuteNonQuery()`).

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
                command.Parameters.Add(new SqlParameter("@ownerName", ownerName));

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

The fix replaces the interpolated `string.Format` SQL text with a parameterized command: the query text now uses a placeholder (`@ownerName`) and the caller-controlled value is passed separately via `SqlParameter`, added to `command.Parameters`. `SqlClient` sends the parameter to SQL Server out-of-band from the command text, so its value is always treated as data, never as SQL syntax, regardless of quotes, semicolons, or comment sequences it contains. This preserves the exact existing behavior (a single `DELETE ... WHERE owner = <value>` statement, same row-count semantics for the `NotFound`/`Ok` branching) while eliminating the injection - no validation, escaping, or allowlisting is needed because the value never enters the SQL grammar.
