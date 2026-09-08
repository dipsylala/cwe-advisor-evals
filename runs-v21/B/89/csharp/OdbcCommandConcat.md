## Verdict

Real exploitable SQL Injection vulnerability. The `searchTerm` parameter is concatenated directly into the SQL query string without parameterization, allowing an attacker to inject arbitrary SQL.

## Source

- **Input source**: `searchTerm` parameter passed to `SearchPartsByDescription(string searchTerm)` (line 17)
- **Data flow**: User-controlled `searchTerm` → string concatenation into SQL query (line 25) → `OdbcCommand` execution (line 29)
- **Exploitation example**: A `searchTerm` value of `%' UNION SELECT 1,user_table_name,3 FROM information_schema.tables WHERE '1'='1` would alter the query logic to extract system information.

## Fix

### File: OdbcCommandConcat.cs

```csharp
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Odbc;

namespace LegacyIntegration.Search
{
    // Connects to a legacy AS/400-backed inventory database via the ODBC bridge driver.
    public class LegacyInventorySearchService
    {
        private readonly string _connectionString;

        public LegacyInventorySearchService(string connectionString)
        {
            _connectionString = connectionString;
        }

        public List<string> SearchPartsByDescription(string searchTerm)
        {
            var results = new List<string>();

            using (var connection = new OdbcConnection(_connectionString))
            {
                connection.Open();

                string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE ?";
                var command = new OdbcCommand(sql, connection);
                command.Parameters.AddWithValue("@searchTerm", "%" + searchTerm + "%");

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
    }
}
```

## Explanation

The fix replaces string concatenation with parameterized queries. The SQL query now uses `?` as a positional placeholder for the LIKE pattern instead of embedding `searchTerm` directly in the query string. The `OdbcCommand.Parameters.AddWithValue()` method binds the `searchTerm` as a separate parameter; ODBC treats this parameter value as data only, never as executable SQL code. The LIKE pattern (`%` + `searchTerm` + `%`) is constructed as the parameter value, not as part of the SQL string, which ensures injection metacharacters in `searchTerm` (such as `'`, `--`, or `UNION`) are escaped and interpreted as literal characters by the database, not as SQL syntax.

## Behaviour changes

- **Query construction**: Changed from string concatenation to parameterized query with positional placeholder (`?`).
- **Parameter binding**: Added `command.Parameters.AddWithValue("@searchTerm", "%" + searchTerm + "%");` to bind the user input as a parameter value.
- **Pattern matching logic**: Functionally identical—the LIKE pattern still works as `%searchTerm%` to match partial descriptions, but the pattern is now safely constructed outside the SQL query string.
- **No breaking changes**: Calling code and return values remain unchanged; the fix is transparent to callers.
