## Verdict

Confirmed. `DeleteByOwner` builds the `DELETE` statement with `string.Format` and the caller-controlled route parameter `ownerName`, so `ExecuteNonQuery()` executes attacker-controlled SQL structure (e.g. `ownerName = "x' OR '1'='1"` deletes every row).

## Source

Route parameter `ownerName` from `[HttpDelete("by-owner/{ownerName}")] DeleteByOwner(string ownerName)` in `WidgetAdminController.cs` - user-controlled with no validation or encoding applied before use.

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

The vulnerable code interpolated `ownerName` directly into the SQL text via `string.Format`, so any quote characters in the value change the query's structure rather than its data. The fix replaces the literal with a `@owner` placeholder and binds the value through `command.Parameters.AddWithValue("@owner", ownerName)`, so the SQL Server driver sends `ownerName` to the server as a typed parameter value, never as part of the command text - injected SQL syntax in the value is treated as literal data and cannot alter the `DELETE` statement's structure. `AddWithValue` is used instead of `Parameters.Add` with an explicit `SqlDbType`/size because the `widgets.owner` column's declared length is not visible in this file and guessing a size risks silently truncating legitimate values; Microsoft's own reference documents `AddWithValue` as a fully parameterized (not merely escaped) alternative, so this is a typing/plan-stability tradeoff and not a gap in the fix. No other behavior changes: the same connection/command lifecycle, the same `ExecuteNonQuery()` sink and return value, and the same not-found/success response mapping are preserved.

## Behaviour changes

None expected. `ExecuteNonQuery()` still returns the affected row count with the same semantics (0 when no widgets match the owner, mapped to `NotFound`, non-zero mapped to `Ok`). Parameter binding does not alter matching semantics for a plain equality comparison (`owner = @owner` matches exactly the same rows `owner = '{ownerName}'` would have matched for any non-malicious value), so legitimate requests behave identically; only the ability to inject SQL syntax through `ownerName` is removed.

**Fix verification:** No .NET/ASP.NET Core project scaffold (target framework, `Microsoft.AspNetCore.Mvc` and `System.Data.SqlClient` package references) was available in the case directory to run a real compile, so this was checked by manual review rather than a compiler: `command.Parameters.AddWithValue(string, object)` is a member of `SqlParameterCollection`, reached through `SqlCommand.Parameters`, both in `System.Data.SqlClient`, which is already imported in the original file - no new `using` directives or dependencies are introduced. The parameter name `@owner` in the command text matches the name passed to `AddWithValue` exactly, and no other call site or signature in the file was changed.
