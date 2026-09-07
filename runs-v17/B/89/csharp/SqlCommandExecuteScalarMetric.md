## Verdict

CONFIRMED. This is a real, exploitable SQL injection vulnerability. User input flows directly from the query string parameter into SQL query construction via string concatenation without any parameterization.

## Source

**Data flow:**
- **Source**: MetricsController.cs, line 17 — the `actor` parameter is accepted from a query string (`[FromQuery] string actor`) without validation
- **Propagation**: MetricsController.cs, line 19 — the `actor` value is passed to `CountEvents()`
- **Sink**: AuditMetricRepository.cs, line 17 — the `actor` parameter is concatenated directly into the SQL query string using `+` operator

**Vulnerable query construction:**
```
command.CommandText = "SELECT COUNT(*) FROM AuditEvents WHERE Actor = '" + actor + "'";
```

**Exploitation example:**
An attacker passing `' OR '1'='1` as the `actor` query parameter produces:
```sql
SELECT COUNT(*) FROM AuditEvents WHERE Actor = '' OR '1'='1'
```
This bypasses the WHERE clause and returns a count of all rows in the table, disclosing the total number of audit events.

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
        command.Parameters.Add("@actor", SqlDbType.NVarChar).Value = actor;
        return (int)command.ExecuteScalar();
    }
}
```

## Explanation

The vulnerability is eliminated by replacing string concatenation with a parameterized query. The fix makes two changes:

1. **Query text**: Replace the concatenated actor value with a placeholder `@actor`. The placeholder is a named parameter that the database engine knows is a value, not query structure.

2. **Parameter binding**: Add the untrusted `actor` value as a parameter using `command.Parameters.Add("@actor", SqlDbType.NVarChar).Value = actor`. This tells the SQL engine to treat the value as data only, never as executable SQL. The `SqlDbType.NVarChar` type declaration is explicit, matching the expected character type for a person/system identifier.

With parameterization, any value in `actor` — including `' OR '1'='1`, `; DROP TABLE AuditEvents; --`, or any other SQL syntax — is treated as a literal string to match against the Actor column. The query structure cannot be altered by the input.

## Behaviour changes

**Functional behaviour:** None. The query returns the same result for any legitimate actor name.

**Performance:** No measurable impact. Parameterized queries are compiled and cached by the SQL Server driver, making them as efficient as dynamic SQL.

**Error handling:** If `actor` is null, the parameter will be assigned a null value, which will match NULL entries in the Actor column (if any). The original vulnerable code would have caused a SQL syntax error if actor were null (incomplete string literal). The fix makes null handling explicit and safe.
