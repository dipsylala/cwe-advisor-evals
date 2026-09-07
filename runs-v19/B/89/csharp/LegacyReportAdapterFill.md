## Verdict

Exploitable. The `region` parameter is user-controlled (from an HTTP query string in LegacyReportController.cs line 17) and is concatenated directly into a SQL query without parameterization, allowing SQL injection at the point of concatenation.

## Source

- **Data source:** HTTP query parameter `region` passed to `LegacyReportController.Customers()` (LegacyReportController.cs, line 17)
- **Entry point:** `LegacyReportRepository.LoadCustomers(string region)` (LegacyReportRepository.cs, line 15)
- **Vulnerable operation:** String concatenation into SQL query (LegacyReportRepository.cs, line 17)
- **Sink:** `SqlDataAdapter.Fill(table)` (LegacyReportRepository.cs, line 20)

An attacker can inject SQL by providing a region value like `' OR '1'='1` or `'; DROP TABLE Customers; --` to manipulate query logic or execute unintended operations.

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
        using var command = new SqlCommand("SELECT CustomerId, Name, Region FROM Customers WHERE Region = @Region", connection);
        command.Parameters.Add("@Region", SqlDbType.NVarChar).Value = region;
        using var adapter = new SqlDataAdapter(command);
        var table = new DataTable("Customers");
        adapter.Fill(table);
        return table;
    }
}
```

## Explanation

The fix replaces string concatenation with a parameterized query. Instead of building SQL by concatenating the untrusted `region` parameter, the query now uses a placeholder (`@Region`) and passes the value as a separate parameter via `SqlCommand.Parameters.Add()`. This ensures the database driver treats the parameter value as data, not as executable SQL code. The parameter is declared with `SqlDbType.NVarChar` to match the expected type for a text column. The `SqlDataAdapter` is initialized with the parameterized `SqlCommand` instead of a raw SQL string, preserving the original execution method and return behavior while closing the injection vulnerability.

## Behaviour changes

- **Added explicit SqlConnection:** The original code relied on SqlDataAdapter to open the connection internally using only the connection string. The fixed code explicitly creates and manages the connection via a `using` statement. This ensures proper resource disposal and is the standard pattern for parameterized queries with SqlCommand.
- **Added SqlCommand instantiation:** The original code passed SQL as a string directly to SqlDataAdapter. The fixed code creates a SqlCommand object with the parameterized query and assigns it to the adapter. This is the required mechanism for parameter binding.
- **Parameter binding:** The untrusted `region` value is now bound as a `SqlParameter` with an explicit type (`SqlDbType.NVarChar`), rather than embedded in the query string. This is the core defence against SQL injection.
- **No change to return contract:** The method still returns a DataTable filled with query results in the same way. The `adapter.Fill(table)` call preserves the original behavior.

## Verification

Syntax validation of the fixed code was performed by examining the C# API contracts:
- `SqlConnection` (System.Data.SqlClient) - standard connection class
- `SqlCommand(string, SqlConnection)` - constructor takes query and connection
- `SqlCommand.Parameters` - SqlParameterCollection property
- `SqlParameterCollection.Add(string, SqlDbType)` - returns SqlParameter with assigned type
- `SqlParameter.Value` - property for setting the parameter value
- `SqlDataAdapter(SqlCommand)` - constructor accepts SqlCommand (parameterized alternative to string-based constructor)

All APIs are from standard System.Data and System.Data.SqlClient namespaces already referenced in the original code. The file requires `using System.Data;` for `SqlDbType` enum, which was already present in the original code. The fix maintains compatibility with the existing dependency set.
