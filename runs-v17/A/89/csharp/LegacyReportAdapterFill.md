## Verdict

Confirmed SQL Injection vulnerability (CWE-89). The `region` parameter is concatenated directly into the SQL query without parameterization, allowing an attacker to inject arbitrary SQL code.

## Source

Line 20 in `LegacyReportRepository.cs`:
```csharp
var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = '" + region + "'";
```

The user-controlled `region` parameter flows from `LegacyReportController.Customers()` query parameter directly into SQL string concatenation without any escaping or parameterization.

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

The vulnerability was remediated by replacing string concatenation with parameterized query execution:

1. **Changed SQL to use parameter placeholder**: The hardcoded string is replaced with `@Region` as a parameterized placeholder, making the SQL structure fixed and immutable.

2. **Created SqlCommand with explicit connection**: Instead of passing a raw SQL string to `SqlDataAdapter`, a `SqlCommand` object is instantiated with the parameterized SQL and a `SqlConnection`. This enables parameter binding.

3. **Added parameter binding**: The `region` input is bound as a parameter using `AddWithValue("@Region", region)`, which treats it as a data value rather than part of the SQL syntax. SQL Server automatically handles escaping and prevents injection.

4. **Passed SqlCommand to adapter**: The `SqlDataAdapter` now receives the `SqlCommand` instead of a raw SQL string, ensuring parameters are properly executed.

This approach separates SQL code from user data, eliminating the injection vector entirely. Any special characters or SQL keywords in the `region` value are treated as literal strings, not executable SQL.
