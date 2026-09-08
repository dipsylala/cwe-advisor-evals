## Verdict

The finding is confirmed. The SQL query on line 17 constructs a dynamic command through string concatenation with an unsanitized user-supplied region parameter, enabling SQL injection attacks.

## Source

File: `LegacyReportRepository.cs`, line 17

```csharp
var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = '" + region + "'";
using var adapter = new SqlDataAdapter(sql, _connectionString);
```

The `region` parameter originates from the controller's `[FromQuery] string region` query parameter (LegacyReportController.cs, line 17), which flows directly into the SQL concatenation without parameterization.

## Fix

### File: LegacyReportRepository.cs

```csharp
using System.Data;
using System.Data.SqlClient;

namespace Cases.SqlInjection;

public sealed class LegacyReportRepository
{
    private readonly string _connectionString;

    public LegacyReportRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public DataTable LoadCustomers(string region)
    {
        var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = @Region";
        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@Region", region);
        using var adapter = new SqlDataAdapter(command);
        var table = new DataTable("Customers");
        adapter.Fill(table);
        return table;
    }
}
```

## Explanation

The remediation replaces string concatenation with parameterized query syntax:

1. **Parameterized query**: Changed the SQL string from `"... WHERE Region = '" + region + "'"` to use a parameter placeholder `@Region`, ensuring the region value is treated as data, not executable SQL.

2. **SqlCommand with parameters**: Instead of passing the SQL string directly to SqlDataAdapter, construct a SqlCommand object and add the region as a parameter via `AddWithValue("@Region", region)`. This separates the query structure from user-supplied values.

3. **Connection management**: Explicitly create and manage the SqlConnection and SqlCommand objects, which are properly disposed via using statements.

The parameter-based approach ensures that any special characters or SQL syntax in the region input (e.g., `' OR '1'='1`) are treated as literal string values rather than SQL command syntax, eliminating the injection vector.
