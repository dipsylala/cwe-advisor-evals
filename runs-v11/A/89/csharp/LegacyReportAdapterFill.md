## Verdict
Confirmed SQL Injection vulnerability. User-supplied `region` parameter is concatenated directly into a SQL query string without parameterization, allowing an attacker to inject arbitrary SQL commands.

## Source
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

The `region` parameter flows directly into the SQL query via string concatenation on line 17. An attacker can supply input like `' OR '1'='1` to bypass the WHERE clause or append additional commands.

## Fix
Replace string concatenation with parameterized query using SqlCommand:

```csharp
public DataTable LoadCustomers(string region)
{
    var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = @Region";
    using var connection = new SqlConnection(_connectionString);
    using var command = new SqlCommand(sql, connection);
    command.Parameters.AddWithValue("@Region", region);
    
    using var adapter = new SqlDataAdapter(command);
    var table = new DataTable("Customers");
    adapter.Fill(table);
    return table;
}
```

## Explanation
Parameterized queries separate SQL structure from user data, preventing injection. The `@Region` placeholder tells SQL Server to expect data, and `AddWithValue()` binds the user input as a parameter value, not as part of the SQL syntax. SQL Server treats the parameter value as literal data and never interprets its contents as executable SQL commands. This approach works with SqlDataAdapter by passing a SqlCommand instead of a raw SQL string.
