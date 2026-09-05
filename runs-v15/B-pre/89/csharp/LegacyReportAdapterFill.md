## Verdict

Exploitable. The `region` parameter flows from an untrusted HTTP query string directly into SQL query construction via string concatenation, allowing an attacker to inject SQL operators and alter query semantics.

## Source

The `region` parameter originates from the HTTP GET query string (`LegacyReportController.cs`, line 19: `[FromQuery] string region`) and is passed to `LoadCustomers(region ?? "")` without validation.

## Fix

**Vulnerable Code:**
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

**Fixed Code:**
```csharp
public DataTable LoadCustomers(string region)
{
    using var connection = new SqlConnection(_connectionString);
    using var command = new SqlCommand(
        "SELECT CustomerId, Name, Region FROM Customers WHERE Region = @region",
        connection);
    command.Parameters.Add("@region", SqlDbType.NVarChar).Value = region;
    
    using var adapter = new SqlDataAdapter(command);
    var table = new DataTable("Customers");
    adapter.Fill(table);
    return table;
}
```

## Explanation

The fix replaces string concatenation with a parameterized query. The SQL query now contains a placeholder `@region` instead of the concatenated region value, and the untrusted input is bound as a parameter via `Parameters.Add()` with an explicit `SqlDbType.NVarChar` type declaration. This ensures the region value is always treated as data, not as SQL syntax. The `SqlDataAdapter` is instantiated with the `SqlCommand` object containing the parameterized query rather than a raw SQL string, which enforces parameter binding at execution time.

## Behaviour changes

The original code created a `SqlDataAdapter` with a raw SQL string and connection string. The fixed code creates an explicit `SqlConnection` and `SqlCommand` with parameterized query, then passes the `SqlCommand` to the `SqlDataAdapter`. The functional behaviour remains identical—the method still returns a `DataTable` with customer records filtered by region—but the transport mechanism changes from implicit connection management to explicit. The `SqlConnection` and `SqlCommand` are wrapped in `using` statements to ensure proper resource disposal, which was implicitly handled by `SqlDataAdapter` in the original code but is now explicit.
