## Verdict

Confirmed - exploitable SQL injection.

## Source

`Customers` action in `LegacyReportController.cs` (line 17-20) reads the `region` query-string parameter via `[FromQuery] string region` and passes it (coalesced to `""` when absent) straight into `LegacyReportRepository.LoadCustomers(region)` with no validation or encoding. The value is fully attacker-controlled.

## Fix

Sink is `SqlDataAdapter.Fill(table)` in `LegacyReportRepository.LoadCustomers`, fed by a `SqlDataAdapter` built from a string concatenating `region` directly into the SQL text (line 17-18):

```csharp
var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = '" + region + "'";
using var adapter = new SqlDataAdapter(sql, _connectionString);
```

An attacker-supplied `region` such as `' OR '1'='1` or `'; DROP TABLE Customers--` alters the query's logic or structure.

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
        command.Parameters.Add("@Region", SqlDbType.NVarChar).Value = region;
        using var adapter = new SqlDataAdapter(command);
        var table = new DataTable("Customers");
        adapter.Fill(table);
        return table;
    }
}
```

## Explanation

The query text no longer contains the `region` value; it is replaced with the placeholder `@Region`, and the value is bound as a `SqlCommand` parameter typed `SqlDbType.NVarChar`. The database driver sends the SQL text and the parameter value separately, so `region` can never be interpreted as SQL syntax regardless of its content - it is always treated as a single string literal for the `Region` column, which eliminates the injection. The `SqlDataAdapter(SqlCommand)` constructor replaces the `SqlDataAdapter(string, string)` constructor used previously, since a parameterized command object - not a raw SQL string - is what carries the bound parameter into the adapter. No `SqlDbType` size is supplied, per the loaded C# guidance, so a `Region` value longer than an implicit default cannot be silently truncated.

## Behaviour changes

- **Connection lifecycle**: the original `SqlDataAdapter(sql, connectionString)` constructor builds its own internal `SqlConnection` from the connection string. The fix constructs that `SqlConnection` explicitly and passes it into the `SqlCommand`/`SqlDataAdapter`. `Fill()` still opens the connection if it is closed and closes it again afterward if it was the one to open it, matching the original adapter's connection-management behavior; the explicit `using var connection` additionally guarantees disposal.
- **Return value**: `adapter.Fill(table)` returns the number of rows affected; both the original and fixed code discard that return value and rely only on `table` being populated - unchanged.
- **Parameter typing**: `region` is now bound as `SqlDbType.NVarChar` with no explicit size, so no value length is rejected or truncated - functionally equivalent to the original unbounded string concatenation for any legitimate input.
- **Query semantics**: for any non-malicious `region` value, the parameterized query returns the identical result set as the original concatenated query (an exact string match against the `Region` column).

Verification: no C# compiler was reachable in this environment, so the fix was checked by hand against the sink contract and the loaded guidance - `SqlConnection`, `SqlCommand`, `SqlDataAdapter`, and `SqlDbType` are all used exactly as documented in `System.Data`/`System.Data.SqlClient` (both already imported by the original file); `Parameters.Add(string, SqlDbType)` returns the new `SqlParameter`, whose `.Value` is assigned per the guidance; the `SqlDataAdapter(IDbCommand)` constructor overload is a standard `System.Data.Common.DbDataAdapter` member. The controller's call site (`LoadCustomers(region ?? "")`) is unchanged, since the method's signature and return type were not modified.
