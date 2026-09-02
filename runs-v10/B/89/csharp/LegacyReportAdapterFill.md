## Verdict

**Confirmed.** SQL injection vulnerability at line 20 of LegacyReportRepository.cs. The `region` parameter from the HTTP request is concatenated directly into the SQL query without parameterization, allowing attackers to inject arbitrary SQL commands.

## Source

**File:** LegacyReportRepository.cs, lines 15–22 (method `LoadCustomers`)
**Entry point:** `region` parameter from `LegacyReportController.Customers()` (line 19 of LegacyReportController.cs), sourced from HTTP query string
**Sink:** `SqlDataAdapter.Fill(table)` at line 20, executing the unparameterized SQL

## Fix

Replace string concatenation with parameterized queries using `SqlCommand` and `SqlDataAdapter`:

```csharp
public DataTable LoadCustomers(string region)
{
    var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = @region";
    using (var connection = new SqlConnection(_connectionString))
    {
        var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.Add("@region", SqlDbType.NVarChar).Value = region;
        using var adapter = new SqlDataAdapter(cmd);
        var table = new DataTable("Customers");
        adapter.Fill(table);
        return table;
    }
}
```

## Explanation

The fix converts the SQL query from string concatenation to a parameterized prepared statement. The `@region` placeholder in the SQL string is bound separately via `cmd.Parameters.Add()`, ensuring the `region` value is treated as data, not executable SQL. This eliminates the injection vector: even if `region` contains SQL metacharacters like `' OR '1'='1`, they are escaped and interpreted as literal string content by the database engine. The `SqlConnection` is now explicitly created and scoped with `using` to ensure proper resource cleanup, and `SqlCommand` is passed to `SqlDataAdapter` instead of a raw SQL string, enabling parameter binding.

## Behaviour changes

- **Before fix:** Query accepts unescaped user input; input like `' OR '1'='1` as region would execute as SQL logic.
- **After fix:** User input is parameterized; the same input is treated as a literal string value for the WHERE clause.
- **Functional impact:** None; the method still returns a DataTable populated with matching customers. Query execution, result handling, and resource cleanup are preserved.
- **Performance:** Negligible; parameterized queries may benefit from query plan caching.
