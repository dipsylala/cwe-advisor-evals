## Verdict

Confirmed. `LoadCustomers` builds a SQL statement by concatenating the caller-supplied `region` value directly into the query text, and `Customers` passes the raw query-string parameter straight through with no validation or encoding.

## Source

`region` originates from `[FromQuery] string region` in `LegacyReportController.Customers`, an untrusted HTTP query-string parameter. It flows unmodified (`region ?? ""`) into `LegacyReportRepository.LoadCustomers(string region)`, where it is concatenated into the SQL text at:

```
var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = '" + region + "'";
```

That string is handed to `new SqlDataAdapter(sql, _connectionString)`, which executes it as a command against the database — the sink. A value such as `' OR '1'='1` or a stacked/batched statement lets an attacker alter the query's logic or run additional statements.

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
        const string sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = @Region";
        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(sql, connection);
        command.Parameters.Add("@Region", SqlDbType.NVarChar, 100).Value = region;

        using var adapter = new SqlDataAdapter(command);
        var table = new DataTable("Customers");
        adapter.Fill(table);
        return table;
    }
}
```

## Explanation

The fix replaces string concatenation with a parameterized command. The query text now contains a placeholder (`@Region`) instead of the raw value, and `region` is bound through `SqlCommand.Parameters` with an explicit `SqlDbType` and length. `SqlDataAdapter` is constructed from that `SqlCommand` (rather than from a raw SQL string), so `Fill` executes the parameterized command instead of a literal string — the database treats the parameter strictly as data, never as part of the SQL grammar, so no input value can change the statement's structure or append additional clauses or statements. `LegacyReportController.cs` needs no change: it already just forwards the query value to the repository, and the sink it feeds is now safe.
