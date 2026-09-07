## Verdict
SQL injection vulnerability confirmed. The `searchTerm` parameter is concatenated directly into the SQL query string on line 25, allowing an attacker to inject malicious SQL commands.

## Source
The vulnerable code constructs a parameterless SQL query by concatenating user-supplied input:

```csharp
string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE '%" + searchTerm + "%'";
var command = new OdbcCommand(sql, connection);
```

An attacker can craft `searchTerm` values like `%' OR '1'='1' --` to alter the query logic or extract unauthorized data.

## Fix
Replace string concatenation with parameterized queries using `OdbcCommand.Parameters`. ODBC uses `?` as the positional parameter placeholder. The pattern wildcards (`%`) are included in the parameter value, which is safe because they are treated as data, not SQL syntax.

### File: OdbcCommandConcat.cs
```csharp
using System;
using System.Collections.Generic;
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
The fix replaces the string concatenation attack surface with parameterized query syntax. The SQL query now uses `?` as a placeholder for the parameter value, and `command.Parameters.AddWithValue()` provides the parameter separately. 

ODBC processes parameters in order: the first `?` corresponds to the first parameter added. The `searchTerm` value is passed as data with embedded wildcard characters (`%` prefix and suffix), preserving the original LIKE search behavior while preventing interpretation of the input as SQL syntax.

This parameterized approach is the standard defense against SQL injection in ODBC and .NET applications.
