## Verdict

The vulnerability is confirmed and remediable.

## Source

`LegacyReportController.cs` line 17 receives untrusted `region` parameter from query string via `[FromQuery] string region`. This parameter is passed directly to `LegacyReportRepository.LoadCustomers()` at line 19 without validation.

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
        using var connection = new SqlConnection(_connectionString);
        var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = @Region";
        using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.Add("@Region", SqlDbType.NVarChar).Value = region;
        using var adapter = new SqlDataAdapter(cmd);
        var table = new DataTable("Customers");
        adapter.Fill(table);
        return table;
    }
}
```

## Explanation

The original code concatenated the untrusted `region` parameter directly into the SQL query string, allowing an attacker to inject SQL commands such as `' OR '1'='1` to bypass the WHERE clause and retrieve all customers.

The fix replaces string concatenation with a parameterized query. The SQL query now uses the `@Region` placeholder, and the region value is bound separately via `Parameters.Add()` with an explicit `SqlDbType.NVarChar` type. This ensures the region value is always treated as data, not as executable SQL. The `SqlCommand` object is then passed to `SqlDataAdapter` instead of a raw SQL string, preserving the parameterization through the sink.

## Behaviour changes

None. The query logic, result set, and return type remain identical. The method signature is unchanged. The only change is the mechanism by which the region parameter is incorporated into the query—from string concatenation to parameterized binding, which closes the injection vector without affecting legitimate functionality.
