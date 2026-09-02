## Verdict

CWE-89 - Exploitable. Confidence: high.

## Source

- **Source**: `actor` query-string parameter, bound via `[FromQuery] string actor` on `MetricsController.ActorCount` (`MetricsController.cs:17`), passed unmodified (only a null-to-empty-string coalesce) into `AuditMetricRepository.CountEvents(actor)` (`MetricsController.cs:19`).
- **Path**: `CountEvents` receives `actor` as a parameter (`AuditMetricRepository.cs:14`) and concatenates it directly into a SQL string literal (`AuditMetricRepository.cs:17`).
- **Sink**: `SqlCommand.ExecuteScalar()` (`AuditMetricRepository.cs:18`), executing `CommandText` built by string concatenation. No validation, escaping, or parameterization occurs anywhere on the path, so a value such as `x' OR '1'='1` or `x'; DROP TABLE AuditEvents--` reaches the database as literal SQL syntax rather than as data.

## Fix

No third-party library is needed - `System.Data.SqlClient` (or `Microsoft.Data.SqlClient`) already provides parameterized commands.

Vulnerable code (`AuditMetricRepository.cs`):

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
        // VULNERABLE: untrusted `actor` concatenated directly into SQL text
        command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = '" + actor + "'";
        return (int)command.ExecuteScalar();
    }
}
```

Fixed code:

```csharp
using System.Data;
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
        command.Parameters.Add("@actor", SqlDbType.NVarChar).Value = actor;
        return (int)command.ExecuteScalar();
    }
}
```

## Explanation

The query text is changed from a string-concatenated literal to a static SQL statement with a `@actor` placeholder, and the untrusted `actor` value is bound through `SqlCommand.Parameters.Add("@actor", SqlDbType.NVarChar).Value = actor` instead of being spliced into the command text. This makes `actor` reach the server strictly as a parameter value in the query's execution plan, so it can no longer alter the statement's structure (no quote-breakout, no injected clauses, no stacked statements) regardless of its content. The `size` argument on `Parameters.Add` is intentionally omitted rather than guessed, since the `Actor` column's declared width is not visible in this call chain and an undersized explicit length would silently truncate legitimate values - omitting it lets the provider size the parameter from the assigned value instead.

## Behaviour changes

None. `CommandText`, `CommandType` (default `Text`), and `ExecuteScalar()`'s return handling (boxed `object` cast to `int`, on the assumption `COUNT(*)` always yields exactly one non-null row) are unchanged; only the mechanism by which `actor` reaches the query changed, from concatenation to a bound parameter.
