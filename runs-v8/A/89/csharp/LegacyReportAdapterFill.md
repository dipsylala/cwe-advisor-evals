## Verdict

SQL injection confirmed. Unsanitized user input is concatenated directly into the SQL query string, allowing attackers to manipulate the query structure and logic.

## Source

File: LegacyReportRepository.cs, line 17

```csharp
var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = '" + region + "'";
```

The `region` parameter originates from the HTTP query string in LegacyReportController.cs line 17 and flows directly into SQL string concatenation without parameterization.

## Fix

```csharp
public DataTable LoadCustomers(string region)
{
    var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = @Region";
    using var adapter = new SqlDataAdapter(sql, _connectionString);
    adapter.SelectCommand.Parameters.AddWithValue("@Region", region ?? "");
    var table = new DataTable("Customers");
    adapter.Fill(table);
    return table;
}
```

## Explanation

The vulnerability allows an attacker to inject SQL fragments through the `region` query parameter. For example, passing `region=' OR '1'='1` would produce the query `SELECT CustomerId, Name, Region FROM Customers WHERE Region = '' OR '1'='1'`, bypassing the WHERE clause entirely and exposing all customer records.

The fix uses a parameterized query with `@Region` as a placeholder and `AddWithValue()` to bind the user-supplied value as a parameter. This separates the SQL structure from the data, ensuring the database driver treats the parameter value as data rather than executable SQL code. Parameterized queries are the standard defense against SQL injection in ADO.NET and are preferred over string concatenation, string escaping, or stored procedures without parameterized inputs.
