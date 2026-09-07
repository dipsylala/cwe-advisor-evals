## Verdict

Real SQL injection via unchecked string concatenation in the SQL query.

## Source

The vulnerability is in `LegacyReportRepository.cs`, line 17. The `region` parameter from user input is concatenated directly into the SQL query without parameterization:

```csharp
var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = '" + region + "'";
```

An attacker can pass input like `' OR '1'='1` to bypass the WHERE clause and retrieve all customers.

## Fix

Replace string concatenation with parameterized queries. Use `SqlCommand` with parameter placeholders, then pass it to `SqlDataAdapter`:

```csharp
public DataTable LoadCustomers(string region)
{
    const string sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = @Region";
    using var connection = new SqlConnection(_connectionString);
    using var command = new SqlCommand(sql, connection);
    command.Parameters.AddWithValue("@Region", region ?? "");
    using var adapter = new SqlDataAdapter(command);
    var table = new DataTable("Customers");
    adapter.Fill(table);
    return table;
}
```

## Explanation

Parameterized queries treat user input as data values, not executable SQL syntax. The `@Region` placeholder is replaced with the actual value only after the SQL statement structure is finalized by the database engine. This separation of structure from data prevents injection attacks regardless of the input content.

The fix uses `SqlCommand` with `Parameters.AddWithValue()` to safely bind the user-supplied `region` value, ensuring it cannot alter the query's intended meaning or structure.
