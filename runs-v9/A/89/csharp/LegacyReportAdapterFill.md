## Verdict

Confirmed. `LegacyReportRepository.LoadCustomers` builds a SQL query by concatenating the caller-supplied `region` value directly into the command text, and that text is passed straight into `SqlDataAdapter`. An attacker who controls `region` can alter the query's structure (classic SQL injection via `Fill`), including closing the quoted literal and appending arbitrary SQL.

## Source

`region` originates from `LegacyReportController.Customers`, bound from the HTTP query string via `[FromQuery] string region` (line 17 of `LegacyReportController.cs`). It is passed unmodified (only null-coalesced to `""`) into `_repository.LoadCustomers(region ?? "")` on line 19, which flows into `LoadCustomers(string region)` in `LegacyReportRepository.cs`.

## Fix

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
        const string sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = @region";
        using var connection = new SqlConnection(_connectionString);
        using var command = new SqlCommand(sql, connection);
        command.Parameters.Add("@region", SqlDbType.NVarChar, 100).Value = region;

        using var adapter = new SqlDataAdapter(command);
        var table = new DataTable("Customers");
        adapter.Fill(table);
        return table;
    }
}
```

## Explanation

The vulnerable sink is the `SqlDataAdapter(sql, _connectionString)` constructor overload, which accepts a raw command string and executes it as-is when `Fill` runs — there is no boundary between the fixed query structure and the `region` data, so any single quote or SQL keyword in `region` becomes part of the executed statement.

The fix replaces string concatenation with a parameterized command: the query text now contains the placeholder `@region` instead of the literal value, and `SqlCommand.Parameters.Add` binds the actual `region` value out-of-band as typed, provider-level data. `SqlDataAdapter` is then constructed from that pre-built `SqlCommand` (the `SqlDataAdapter(IDbCommand)` overload) rather than from a bare SQL string, so `Fill` executes the same parameterized command — the database driver sends the value separately from the query plan, so it can never be interpreted as SQL syntax regardless of its contents. Explicitly typing and sizing the parameter (`SqlDbType.NVarChar, 100`) also avoids implicit-conversion mismatches and truncates unexpectedly long input at the ADO.NET layer rather than at the database.

To verify, supply a `region` value containing a single quote plus trailing SQL (e.g. `' OR '1'='1`, or a `UNION SELECT` payload) and confirm the query returns rows filtered to that literal string (i.e., no matches) instead of altering the result set or throwing a syntax-driven error — and confirm legitimate region values still return the expected rows.
