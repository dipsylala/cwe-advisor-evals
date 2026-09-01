## Verdict

Exploitable. The `region` parameter flows unvalidated from an HTTP query string through `LegacyReportController.Customers([FromQuery] string region)` into `LegacyReportRepository.LoadCustomers(string region)`, where it is concatenated directly into a SQL query string at line 17. This query is then passed to `SqlDataAdapter` and executed at line 20, allowing an attacker to manipulate the query structure.

Example attack payload: `region = "' OR '1'='1"` produces the query `SELECT CustomerId, Name, Region FROM Customers WHERE Region = '' OR '1'='1'`, returning all records instead of filtering by region.

## Source

**Parameter:** `region` from `LegacyReportController.Customers([FromQuery] string region)`

**Data path:** HTTP query string → Controller parameter → `LoadCustomers()` argument → String concatenation into SQL at line 17

## Fix

**Vulnerable code (line 15–22):**
```csharp
public DataTable LoadCustomers(string region)
{
    var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = '" + region + "'";
    using var adapter = new SqlDataAdapter(sql, _connectionString);
    var table = new DataTable("Customers");
    adapter.Fill(table);
    return table;
}
```

**Fixed code:**
```csharp
public DataTable LoadCustomers(string region)
{
    using var connection = new SqlConnection(_connectionString);
    using var command = new SqlCommand(
        "SELECT CustomerId, Name, Region FROM Customers WHERE Region = @region",
        connection
    );
    command.Parameters.Add("@region", SqlDbType.NVarChar).Value = region;
    
    using var adapter = new SqlDataAdapter(command);
    var table = new DataTable("Customers");
    adapter.Fill(table);
    return table;
}
```

## Explanation

The fix replaces string concatenation with parameterized SQL using `SqlCommand.Parameters.Add()`. The untrusted `region` value is now bound as a parameter (`@region`) with explicit type `SqlDbType.NVarChar`, ensuring it is treated as data rather than query structure. The SQL Server driver will never interpret the parameter value as executable SQL, regardless of special characters or SQL keywords it contains. The `SqlCommand` is passed to `SqlDataAdapter` instead of a raw SQL string, preserving the same return type and behavior while eliminating the injection path.

## Behaviour changes

**SqlConnection lifecycle:** The original code passed a connection string to `SqlDataAdapter`, which managed the connection internally. The fixed code creates an explicit `SqlConnection` with a `using` statement, maintaining the same resource-disposal guarantee but making it explicit in the code. The connection opens when `SqlDataAdapter.Fill()` executes and closes when the `using` block exits.

**No other changes:** `SqlDataAdapter.Fill()` returns void as before, the `DataTable` is populated with query results, and the method's return type is unchanged.
