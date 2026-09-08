## Verdict

SQL injection vulnerability confirmed. Line 17 constructs the SQL command by concatenating an untrusted `actor` parameter directly into the query string. An attacker can inject arbitrary SQL by supplying input like `' OR '1'='1`.

## Source

**File:** `AuditMetricRepository.cs`  
**Method:** `CountEvents(string actor)`  
**Lines:** 17-18

The vulnerable code:
```csharp
command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = '" + actor + "'";
return (int)command.ExecuteScalar();
```

**Call chain:** `MetricsController.ActorCount` (receives untrusted query parameter) → `AuditMetricRepository.CountEvents` (concatenates into SQL) → `SqlCommand.ExecuteScalar` (executes unsafe query).

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

The fix replaces string concatenation with a parameterized query. Instead of embedding the `actor` value directly in the SQL string, a named parameter `@actor` is declared in the query, and the actual value is passed separately via `command.Parameters.AddWithValue()`. This ensures the `actor` value is treated as literal data, not as executable SQL syntax, preventing injection regardless of its contents.

