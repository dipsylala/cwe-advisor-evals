## Verdict

Exploitable. The untrusted `region` query parameter flows directly into SQL concatenation without parameterization, allowing injection of arbitrary SQL logic via the WHERE clause.

## Source

`LegacyReportController.cs` line 19: HTTP query parameter `region` is passed to `LoadCustomers()` without validation or sanitization.

## Fix

Replace string concatenation with parameterized queries using `SqlCommand.Parameters`:

**Vulnerable code** (line 15-22):
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

**Fixed code**:
```csharp
public DataTable LoadCustomers(string region)
{
    var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = @Region";
    using var connection = new SqlConnection(_connectionString);
    using var command = new SqlCommand(sql, connection);
    command.Parameters.Add("@Region", SqlDbType.NVarChar).Value = region;
    
    using var adapter = new SqlDataAdapter(command);
    var table = new DataTable("Customers");
    adapter.Fill(table);
    return table;
}
```

## Explanation

The fix replaces string concatenation with a parameterized query. The SQL structure is now fixed (`WHERE Region = @Region`), and the `region` value is bound separately via `SqlCommand.Parameters.Add()` with an explicit `SqlDbType.NVarChar` type declaration. This ensures the database driver treats `region` as data, never as executable SQL, preventing injection regardless of its content. The parameter is passed through the `SqlCommand` object to the `SqlDataAdapter`, which executes the safely-parameterized query.

## Behaviour changes

No functional changes. The query returns the same result set. Performance is identical or slightly improved due to potential query plan reuse from parameterized queries. The `SqlDataAdapter` continues to fill the DataTable as before, maintaining API compatibility with callers.
