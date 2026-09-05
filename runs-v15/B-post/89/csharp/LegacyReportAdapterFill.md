## Verdict

Exploitable. The `region` parameter is unsanitized and directly concatenated into the SQL query, allowing SQL injection.

## Source

The `region` parameter in the `LoadCustomers` method (line 15) accepts untrusted user input.

## Fix

Replace string concatenation with parameterized queries using `SqlCommand.Parameters`:

**Vulnerable code:**
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
    var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = @Region";
    using var connection = new SqlConnection(_connectionString);
    using var cmd = new SqlCommand(sql, connection);
    cmd.Parameters.Add("@Region", SqlDbType.NVarChar).Value = region;
    
    using var adapter = new SqlDataAdapter(cmd);
    var table = new DataTable("Customers");
    adapter.Fill(table);
    return table;
}
```

## Explanation

The fix replaces string concatenation with a parameterized query. The `@Region` placeholder separates SQL structure from data: the parameter value is transmitted to the database as data, never interpreted as SQL syntax. `SqlCommand.Parameters.Add()` with an explicit `SqlDbType.NVarChar` type ensures the parameter is correctly bound. The `SqlDataAdapter` constructor now accepts a `SqlCommand` object instead of a raw SQL string, enforcing parameterized execution. The `SqlConnection` is required when using `SqlCommand` and is disposed via the `using` statement, preserving the original resource-management behaviour.

## Behaviour changes

No user-visible behaviour changes. The query still returns the same rows, filtering by the `region` parameter. The only change is how that parameter reaches the database: as data rather than executable SQL, eliminating the injection vector.
