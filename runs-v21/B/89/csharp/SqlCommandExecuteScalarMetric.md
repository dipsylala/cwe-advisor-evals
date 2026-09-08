## Verdict

exploitable

## Source

Query parameter `actor` from `MetricsController.ActorCount([FromQuery] string actor)` in MetricsController.cs line 17.

## Fix

### File: AuditMetricRepository.cs

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
        command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = @Actor";
        command.Parameters.Add("@Actor", SqlDbType.NVarChar).Value = actor;
        return (int)command.ExecuteScalar();
    }
}
```

## Explanation

The original code constructed a SQL query by concatenating the untrusted `actor` parameter directly into the query string: `"SELECT COUNT(*) FROM AuditEvents WHERE Actor = '" + actor + "'"`. This allows an attacker to inject SQL by providing input like `' OR '1'='1`, which would modify the query logic. The fix replaces string concatenation with a parameterized query using `SqlCommand.Parameters.Add()`, which ensures the `actor` value is always treated as data, never as query structure. The parameter placeholder `@Actor` marks where the value will be safely bound, and the explicit `SqlDbType.NVarChar` typing ensures type safety. The `using System.Data;` import was added because `SqlDbType` enum resides in that namespace.

## Behaviour changes

None. The fix preserves the original behavior: `ExecuteScalar()` still returns the count as an object (cast to `int`), error handling remains unchanged, and the parameterization does not alter the semantics of the query execution or return value.

