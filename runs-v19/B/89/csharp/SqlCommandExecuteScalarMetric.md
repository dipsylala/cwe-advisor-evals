## Verdict

SQL injection vulnerability confirmed. Line 17 of AuditMetricRepository.cs concatenates untrusted `actor` parameter directly into SQL query string, allowing arbitrary SQL injection. Attack vector: actor value `' OR '1'='1` bypasses WHERE clause filtering.

## Source

- **Entry point**: MetricsController.ActorCount() receives untrusted `actor` from HTTP query string parameter
- **Sink**: AuditMetricRepository.CountEvents() concatenates actor into SQL via string concatenation at line 17, executed by ExecuteScalar() at line 18
- **Call chain**: HTTP query → MetricsController.ActorCount() → AuditMetricRepository.CountEvents() → ExecuteScalar()

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
        command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = @actor";
        command.Parameters.Add("@actor", SqlDbType.NVarChar).Value = actor;
        return (int)command.ExecuteScalar();
    }
}
```

## Explanation

The fix replaces string concatenation with parameterized queries. The vulnerable line:

```csharp
command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = '" + actor + "'";
```

is replaced with a parameterized query:

```csharp
command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = @actor";
command.Parameters.Add("@actor", SqlDbType.NVarChar).Value = actor;
```

This ensures the `actor` value is always treated as data, never as query structure. The SQL parser cannot interpret the parameter value as executable SQL regardless of its content. The `using System.Data;` import is added to make `SqlDbType` available. `SqlDbType.NVarChar` is appropriate for string values in SQL Server. The fix preserves the original method signature, return type, and execution semantics (ExecuteScalar() still returns the same scalar value).

## Behaviour changes

No behaviour changes. The query returns the same result set and value for all valid inputs. The only difference is that SQL special characters in `actor` are now treated as literal characters, not query syntax. Invalid inputs that previously could have corrupted query logic (e.g., `' OR '1'='1`) now search for a literal actor name matching that exact string, which will not exist in practice.
