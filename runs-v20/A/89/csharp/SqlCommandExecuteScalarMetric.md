## Verdict

Confirmed. `AuditMetricRepository.CountEvents` builds a SQL string by concatenating the caller-supplied `actor` value directly into the `WHERE` clause, then executes it with `command.ExecuteScalar()`. Any value containing a single quote breaks out of the string literal and lets an attacker alter the query (e.g. force a truthy `WHERE` clause, or run a stacked query depending on the driver/permissions).

## Source

`MetricsController.ActorCount` reads `actor` from `[FromQuery]` (untrusted, attacker-controlled HTTP query string), defaults a null to `""`, and passes it unmodified into `AuditMetricRepository.CountEvents(actor)`. `CountEvents` concatenates it into `command.CommandText` at line 18 and calls `ExecuteScalar()` on line 18 — the same line is both the concatenation and the sink since the string is built and assigned there before execution.

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
        command.Parameters.Add(new SqlParameter("@actor", System.Data.SqlDbType.NVarChar, 256) { Value = actor });
        return (int)command.ExecuteScalar();
    }
}
```

## Explanation

The fix replaces string concatenation with a parameterized query: the `WHERE Actor = @actor` clause uses a placeholder, and the actual `actor` value is bound as a `SqlParameter` rather than being spliced into the command text. `SqlClient` sends the parameter value to SQL Server separately from the query text, so the database always treats it as a single literal value for the `Actor` column — it can never be interpreted as SQL syntax, regardless of quotes, semicolons, or comment sequences it contains. This is the standard, minimal fix for this pattern: it removes the injection entirely without changing the method's signature, return type, or behavior for legitimate input, so `MetricsController` requires no changes.

An explicit `SqlDbType.NVarChar` with a length bound is used instead of relying on ADO.NET's implicit type inference from the CLR string, since implicit parameter typing for string values can occasionally produce a type/size mismatch against the column's actual definition; binding the type and a reasonable length explicitly avoids that ambiguity while keeping the same value semantics as the original query.
