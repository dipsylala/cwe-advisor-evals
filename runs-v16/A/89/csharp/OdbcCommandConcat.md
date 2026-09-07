## Verdict

The vulnerability is confirmed. Line 25 constructs a SQL query by concatenating the `searchTerm` parameter directly into the query string without sanitization or parameterization, enabling SQL injection attacks.

## Source

```csharp
string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE '%" + searchTerm + "%'";
var command = new OdbcCommand(sql, connection);
```

An attacker can inject SQL metacharacters through `searchTerm` to modify query logic, extract unauthorized data, or corrupt the database.

## Fix

Replace string concatenation with parameterized queries using `OdbcCommand.Parameters`:

```csharp
string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE ?";
var command = new OdbcCommand(sql, connection);
command.Parameters.AddWithValue("@searchPattern", "%" + searchTerm + "%");
```

The corrected method:

```csharp
public List<string> SearchPartsByDescription(string searchTerm)
{
    var results = new List<string>();

    using (var connection = new OdbcConnection(_connectionString))
    {
        connection.Open();

        string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE ?";
        var command = new OdbcCommand(sql, connection);
        command.Parameters.AddWithValue("@searchPattern", "%" + searchTerm + "%");

        using (OdbcDataReader reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                string partNumber = reader["PartNumber"].ToString();
                string description = reader["Description"].ToString();
                string warehouseCode = reader["WarehouseCode"].ToString();
                results.Add(string.Format("{0} ({1}) - {2}", partNumber, description, warehouseCode));
            }
        }
    }

    return results;
}
```

## Explanation

SQL injection occurs when untrusted input is concatenated directly into SQL strings. The `OdbcCommand` class supports parameterized queries using the `Parameters` collection, which separates query structure from data. The ODBC driver treats parameter values as literals, not executable SQL, preventing injection attacks.

The wildcard characters `%` are safely applied to the parameter value before binding, preserving the intended `LIKE` pattern matching while keeping the SQL structure immutable. This approach is portable, performant, and the standard defense for SQL injection across all .NET data access layers.
