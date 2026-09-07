## Verdict

Confirmed SQL injection vulnerability in AuditMetricRepository.cs line 17. The actor parameter is concatenated directly into a SQL query string without parameterization, allowing an attacker to inject arbitrary SQL commands.

## Source

**AuditMetricRepository.cs, line 14-19:**

```csharp
public int CountEvents(string actor)
{
    using var command = _connection.CreateCommand();
    command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = '" + actor + "'";
    return (int)command.ExecuteScalar();
}
```

The vulnerable line concatenates the untrusted `actor` parameter directly into the SQL command string.

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
        command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = @Actor";
        command.Parameters.AddWithValue("@Actor", actor);
        return (int)command.ExecuteScalar();
    }
}
```

## Explanation

The vulnerability stems from concatenating user-supplied input (`actor`) directly into a SQL query string. An attacker can inject SQL syntax such as `' OR '1'='1` to bypass the WHERE clause or inject additional commands.

The fix uses parameterized queries via `SqlParameter`. The `@Actor` placeholder in the query string is bound to the actual actor value through `command.Parameters.AddWithValue()`. The SQL engine treats the parameter value as data only, not executable SQL code, preventing injection attacks.

This approach:
- Separates query structure from data
- Neutralizes special characters in the parameter value
- Allows the SQL engine to properly parse the query
- Is the standard defense against SQL injection in ADO.NET
