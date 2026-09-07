## Verdict

SQL Injection via string concatenation. User input from `region` query parameter is concatenated directly into the SQL query without parameterization, allowing an attacker to inject malicious SQL. The vulnerability appears at line 17 in the string concatenation, and is executed at line 20 when `adapter.Fill(table)` executes the malformed SQL.

## Source

The `region` parameter originates from the HTTP query string in `LegacyReportController.cs` line 17, passed directly to `LoadCustomers()` without validation.

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

The fix replaces string concatenation with parameterized queries using `SqlCommand.Parameters`. Instead of building SQL by concatenating the `region` value directly into the query string, the placeholder `@Region` marks where the parameter goes, and `Parameters.Add()` binds the actual value separately. This ensures the database driver treats the user input as data, not as SQL code, preventing injection. The `SqlCommand` object is then passed to `SqlDataAdapter` (which accepts a `SqlCommand` in its constructor) to maintain the same calling interface and return behavior.

## Behaviour changes

None. The fix maintains the same return type (`DataTable`), connection handling (connection opened and closed by SqlDataAdapter), and data retrieval semantics. Only the mechanism of parameter passing changes from unsafe concatenation to safe parameterization.
