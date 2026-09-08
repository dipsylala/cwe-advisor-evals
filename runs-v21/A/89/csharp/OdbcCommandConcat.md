## Verdict
VULNERABLE. Line 25 concatenates unsanitized user input (`searchTerm`) directly into the SQL query string. An attacker can inject SQL syntax (e.g., `' OR '1'='1`) by controlling the search term, bypassing the LIKE predicate and returning unauthorized data or executing arbitrary SQL commands.

## Source
The vulnerability exists in the SQL query construction at line 25:
```csharp
string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE '%" + searchTerm + "%'";
```

The `searchTerm` parameter is received from the caller and directly concatenated into the SQL string without any parameterization or escaping. This allows an attacker to inject SQL syntax.

## Fix
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
The fix replaces string concatenation with parameterized query syntax:

1. **Query placeholder**: The SQL query now uses `?` (ODBC positional parameter syntax) instead of concatenating the search term directly.

2. **Parameter binding**: `command.Parameters.AddWithValue()` binds the user-supplied value as a parameter. The wildcard characters (`%`) are included in the parameter value, not in the query string itself.

3. **Defense mechanism**: ODBC drivers treat parameter values as data, not executable SQL syntax. Any special characters in `searchTerm` (like quotes, semicolons, or SQL keywords) are automatically escaped and neutralized by the database driver before the query is executed.

This parameterized approach is the standard defense against SQL injection in C# and works consistently across all ODBC-compliant databases.
