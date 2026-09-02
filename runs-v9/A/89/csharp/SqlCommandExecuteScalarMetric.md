## Verdict

Confirmed. `AuditMetricRepository.CountEvents` builds SQL by string-concatenating the `actor` parameter directly into the command text, allowing SQL injection.

## Source

`MetricsController.ActorCount` (line 19) takes `actor` from `[FromQuery] string actor`, an untrusted HTTP query-string parameter, and passes it straight to `AuditMetricRepository.CountEvents(actor)` with no validation or encoding.

## Fix

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

The vulnerable line built the query with `"... WHERE Actor = '" + actor + "'"`, so any single quote in `actor` breaks out of the string literal and lets an attacker append arbitrary SQL (e.g. `actor = "' OR '1'='1"` returns the count of all rows, or a stacked/UNION payload could exfiltrate data from other tables). Because `actor` flows in unmodified from the `actor-count` query-string parameter, it is fully attacker-controlled.

The fix replaces the literal with a parameter placeholder (`@actor`) and binds the value through `SqlParameter`, using `System.Data.SqlClient`'s ADO.NET parameterization. The database driver sends the value out-of-band from the SQL text, so it is always treated as data, never as part of the query grammar, regardless of what characters it contains - no escaping or quoting logic is needed and none of the classic injection payloads have any effect. An explicit `SqlDbType.NVarChar` with a bounded length is used rather than relying on type inference, which also avoids implicit conversions that can defeat index usage on the `Actor` column.
