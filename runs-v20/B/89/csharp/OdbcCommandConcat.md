## Verdict

- **cwe_id**: CWE-89
- **location**: `OdbcCommandConcat.cs`, line 29 (`command.ExecuteReader()`), root-caused to the string concatenation at line 25
- **verdict**: exploitable
- **confidence**: high

## Source

- **Source**: `searchTerm`, the parameter to `LegacyInventorySearchService.SearchPartsByDescription(string searchTerm)`. It is attacker-controlled input from a caller (e.g. a search box or API parameter) with no validation or escaping applied anywhere in the method.
- **Sink**: `OdbcCommand.ExecuteReader()` at line 29, executing a SQL string built by direct concatenation at line 25:
  `"SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE '%" + searchTerm + "%'"`.
- **Data flow**: `searchTerm` flows unmodified from the method parameter directly into the SQL string literal, then into `new OdbcCommand(sql, connection)` and `command.ExecuteReader()`. No intermediate validation, parameterization, or escaping breaks the taint path. A value such as `' UNION SELECT ...--` closes the quoted `LIKE` literal and injects arbitrary SQL that runs with the privileges of the configured ODBC connection.

Sink contract (established before fixing):
- **Returns**: an `OdbcDataReader` that the `using` block iterates via `.Read()`, projecting three columns per row into a formatted string appended to `results`.
- **Discards**: nothing beyond the normal row cursor; no additional result sets or output parameters are read.
- **Arguments left implicit**: `OdbcCommand`'s `CommandType` defaults to `Text` (already what's needed here); no command timeout override is set, so the connection's default applies - unchanged by this fix.
- **Failure behaviour**: driver/database errors surface as `OdbcException` from `ExecuteReader()`, uncaught here (propagates to the caller) - unchanged by this fix.

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
                command.Parameters.Add("@searchTerm", OdbcType.VarChar).Value = "%" + searchTerm + "%";

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

The query text no longer contains any user data: the `LIKE` predicate now uses `?`, the ODBC positional placeholder, in place of the concatenated `'%...%'` literal. The `%` wildcards move into the bound value itself (`"%" + searchTerm + "%"`), which is supplied through `OdbcParameter` via `command.Parameters.Add("@searchTerm", OdbcType.VarChar).Value = ...` rather than substituted into the SQL text. `OdbcCommand`/`OdbcParameter` are positional under the ODBC driver manager - the parameter's name is a label for the code, not a bound placeholder name in the SQL - so the single `?` and the single `Add` call stay correctly paired, and an explicit `OdbcType.VarChar` is used instead of `AddWithValue()` so the driver is told the parameter's type rather than inferring it. Because the driver now sends `searchTerm` to the database as a data value bound to the query plan, any quotes, `UNION`, comment markers, or other SQL metacharacters it contains are treated as literal characters to match against `Description`, not as query syntax, closing the injection. `%` and `_` remain LIKE wildcards within the bound value (unchanged from the original, unparameterized query's behavior), so a search term containing them still matches loosely; this is a pre-existing property of the query, not a change introduced by the fix.

## Behaviour changes

- **none** beyond closing the weakness. The result set, column projection, row formatting, connection lifecycle, and exception behavior on driver/database error are all unchanged. The only differences from the original are: (1) the SQL text uses `?` instead of an inline `'%...%'` literal, and (2) the search value (with its `%` wildcards) is now supplied via a bound `OdbcParameter` instead of string concatenation - both are the mechanism of the fix itself, not incidental behavior changes.

## Verification

Compiled with the .NET SDK (`dotnet build`, .NET 10 SDK, `System.Data.Odbc` package referenced) against a scratch copy of the fixed file outside the repository. Build succeeded with 0 errors (the file produces three pre-existing nullable-reference warnings on the `reader["..."]` casts identical to the original code, unrelated to this fix). This confirms `OdbcConnection`, `OdbcCommand`, `OdbcDataReader`, `OdbcType.VarChar`, and the `OdbcParameterCollection.Add(string, OdbcType)` overload used in the fix all exist and are used with correct signatures.

## Assumptions

- The C# language guidance (`cwe/89/csharp/INDEX.md`) is written primarily around `SqlCommand`/EF Core; no ODBC-specific example is given there. Applied its general parameterization principle (explicit type via `Parameters.Add` rather than `AddWithValue`) to the ODBC API, and confirmed by compilation that `System.Data.Odbc` exposes the equivalent `OdbcType` enum and `OdbcParameterCollection.Add(string, OdbcType)` overload used here. ODBC parameters are positional (bound by `?` order, not by the name string passed to `Add`), which is a driver-manager-level distinction from the named `@param` style shown in the loaded guidance's `SqlCommand` examples; this is reflected in the fix (single `?`, single parameter, order-matched) and does not affect its correctness with only one parameter.
