## Verdict

Confirmed. `AuditMetricRepository.CountEvents` builds a SQL `WHERE` clause by concatenating an untrusted string directly into `CommandText`, then executes it with `SqlCommand.ExecuteScalar()`. Classic CWE-89 SQL injection.

## Source

`MetricsController.ActorCount([FromQuery] string actor)` reads `actor` from the request query string (attacker-controlled), passes it through `actor ?? ""` and into `_repository.CountEvents(actor)`. `CountEvents` concatenates the value directly into the SQL text:

```
command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = '" + actor + "'";
```

which reaches the sink `command.ExecuteScalar()` (`System.Data.SqlClient.SqlCommand.ExecuteScalar`). No validation, escaping, or parameterization occurs anywhere on this path, so the finding is exploitable as reported - an `actor` value such as `' OR '1'='1` or a stacked/UNION payload alters the query's logic.

## Fix

### File: AuditMetricRepository.cs

```csharp
using System.Data.SqlClient;

namespace Cases.SqlInjection;

public sealed class AuditMetricRepository
{
    private readonly SqlConnection _connection;

    public AuditMetricRepository(SqlConnection connection)
    {
        _connection = connection;
    }

    public int CountEvents(string actor)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = @actor";
        command.Parameters.AddWithValue("@actor", actor);
        return (int)command.ExecuteScalar();
    }
}
```

## Explanation

The fix replaces string concatenation with a parameterized query: `@actor` is a placeholder bound via `SqlCommand.Parameters.AddWithValue`, so the ADO.NET provider sends the query text and the `actor` value to SQL Server separately. The database can no longer interpret any part of `actor` as SQL syntax - it is always treated as a single scalar value compared against the `Actor` column - which closes the injection regardless of what characters the value contains. `AddWithValue` was chosen over `Parameters.Add("@actor", SqlDbType.NVarChar, <size>)` deliberately: the schema's actual column type/length is not available in this file, and supplying a guessed `SqlDbType`/size could silently truncate legitimate `actor` values that the original, unparameterized query never truncated. `AddWithValue` infers the parameter's type and length from the runtime string, so it parameterizes just as completely while preserving the original value-handling behavior exactly (the C# guidance notes this is a legitimate convenience choice, not a defect, for this reason). No other logic changed.

## Behaviour changes

- None functionally: for any input that does not attempt SQL injection, the query returns the identical `COUNT(*)` result as before. `ExecuteScalar()`'s return type, the cast to `int`, and error/throw behavior (e.g. `SqlException` on connection/database errors) are all unchanged.
- The only behavioral difference is for previously-malicious inputs: an `actor` value containing SQL metacharacters (quotes, `--`, `;`, etc.) is now always matched literally against the `Actor` column instead of altering the query, so such inputs will now correctly return a count of 0 (or whatever legitimately matches that literal string) instead of executing attacker-controlled SQL.
- Verification performed: the fixed file was copied to a scratch project (`dotnet build` with `net8.0`, referencing `System.Data.SqlClient` 4.9.0) and compiled successfully - 0 errors, only the pre-existing `CS0618` obsolescence warning on `SqlConnection` that is also present in the original, unmodified code (unrelated to this fix).
