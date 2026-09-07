## Verdict

The vulnerability on line 29 is confirmed. Line 25 constructs an SQL query by concatenating the untrusted `searchTerm` parameter directly into the query string. When `ExecuteReader()` is called on line 29, the malicious input can manipulate the SQL logic - for example, `' OR '1'='1` would bypass the LIKE condition and return all records.

## Source

The `searchTerm` parameter enters at line 17 as a public method argument with no validation. It flows directly to line 25 where it is concatenated into a SQL query string without parameterization.

## Fix

Replace string concatenation with parameterized query binding. The parameter placeholder in ODBC is `?` (positional), and parameters are added to the `OdbcCommand.Parameters` collection with explicit type declarations.

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
                command.Parameters.Add("@searchTerm", OdbcType.VarChar, 255).Value = "%" + searchTerm + "%";

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

The fix introduces two key changes to line 25-26:

1. **Replace string concatenation with parameterized placeholder:** The query now uses `?` instead of `"'%" + searchTerm + "%'"`. This tells ODBC to treat the subsequent parameter value as data, not as SQL structure.

2. **Bind the parameter explicitly:** `command.Parameters.Add()` registers the parameter with an explicit type (`OdbcType.VarChar`), size (255), and value. The wildcard characters remain in the application code (`"%" + searchTerm + "%"`), not in the SQL query structure, so they are part of the search pattern data, not query syntax.

When `ExecuteReader()` runs, the database driver will not interpret any SQL metacharacters in the bound value - the entire `"%" + searchTerm + "%"` string is treated as literal comparison data for the LIKE operator.

## Behaviour changes

**Before the fix:** An attacker supplying `searchTerm = "' OR '1'='1"` results in the query:
```sql
SELECT ... WHERE Description LIKE '%' OR '1'='1%'
```
This returns all records because the `OR '1'='1` clause is parsed as query logic, not as literal data.

**After the fix:** The same input is bound as a parameter value, and the database interprets it as:
```sql
SELECT ... WHERE Description LIKE ?
-- with parameter: "%" + "' OR '1'='1" + "%" = "%' OR '1'='1%"
```
The query searches for literal strings containing `' OR '1'='1`, finding no matches and returning only legitimate records matching the search term. SQL injection is prevented because the input never reaches the SQL parser.
