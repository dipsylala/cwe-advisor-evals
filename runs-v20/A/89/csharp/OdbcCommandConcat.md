## Verdict
Confirmed. `SearchPartsByDescription` builds the SQL text by concatenating `searchTerm` directly into a `LIKE` clause, then executes it with `OdbcCommand.ExecuteReader()`. An attacker-controlled search term can close out the string literal and inject arbitrary SQL.

## Source
`searchTerm`, the method parameter to `LegacyInventorySearchService.SearchPartsByDescription(string searchTerm)` (line 17). It flows unmodified into the `sql` string concatenation at line 25.

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

                const string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE ?";
                var command = new OdbcCommand(sql, connection);
                command.Parameters.AddWithValue("?", "%" + EscapeLikeWildcards(searchTerm) + "%");

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

        // Escapes LIKE wildcard characters so the search term is matched literally,
        // not interpreted as a pattern by the database.
        private static string EscapeLikeWildcards(string value)
        {
            return value
                .Replace("\\", "\\\\")
                .Replace("%", "\\%")
                .Replace("_", "\\_");
        }
    }
}
```

## Explanation
The ODBC driver interface uses positional `?` placeholders rather than named parameters. Replacing the concatenated literal with a single `?` placeholder and supplying `searchTerm` through `OdbcCommand.Parameters.AddWithValue` sends the value to the database as data, not as part of the SQL text, so it cannot terminate the string literal or alter the query's structure regardless of what characters it contains.

The value is still wrapped with `%` wildcards to preserve the original substring-match behavior, so `EscapeLikeWildcards` neutralizes any `%`, `_`, or `\` the user supplies before the wildcards are added - otherwise a search term containing those characters could still change which rows match, even though it could no longer alter the query's structure. This is LIKE-pattern escaping, not a security allowlist, so legitimate search terms (including punctuation) continue to work unchanged aside from the escaped wildcard characters.

Most ODBC drivers treat `\` as the default LIKE escape character; if this bridge driver differs, use its `ESCAPE` clause with the corresponding escape character instead.
