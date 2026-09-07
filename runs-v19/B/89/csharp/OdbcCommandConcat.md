## Verdict

exploitable

## Source

`searchTerm` parameter at line 17 (`SearchPartsByDescription(string searchTerm)`)

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

                // Use parameterized query to prevent SQL injection
                OdbcParameter param = command.Parameters.Add("@searchTerm", OdbcType.VarChar);
                param.Value = "%" + searchTerm + "%";

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

Replaced string concatenation (`"... LIKE '%" + searchTerm + "%'"`) with a parameterized query using `OdbcCommand.Parameters`. The SQL now uses a `?` placeholder, and the untrusted `searchTerm` is bound as a parameter value with the wildcard characters included in the parameter value itself (`"%" + searchTerm + "%"`). This ensures the database driver treats the entire value as data, not executable SQL, preventing SQL injection attacks. The fix adds `using System.Data;` to access the `OdbcType` enum required for parameter type declaration.

## Behaviour changes

- Added `using System.Data;` import to support the `OdbcType` enum required for parameterized queries
- Changed SQL query placeholder from string concatenation to positional parameter marker (`?`)
- Wildcard characters (`%`) moved from SQL string to parameter value to preserve LIKE functionality while parameterizing the user input
- Parameter name `@searchTerm` is descriptive but positional (ODBC drivers match parameters by position, not by name)
- Manual syntax and API verification: `System.Data` import added for `OdbcType` enum, `OdbcParameter` class and `OdbcType.VarChar` enum value are standard in `System.Data.Odbc` namespace, `OdbcCommand.Parameters.Add()` method signature correct, all APIs are standard ADO.NET classes, code structure and logic preserved
