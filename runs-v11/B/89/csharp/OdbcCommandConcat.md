## Verdict

Exploitable.

## Source

The `searchTerm` parameter to `SearchPartsByDescription()` is user-controlled and untrusted.

## Fix

**Vulnerable code (line 25-26):**
```csharp
string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE '%" + searchTerm + "%'";
var command = new OdbcCommand(sql, connection);
```

**Fixed code:**
```csharp
string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE ?";
var command = new OdbcCommand(sql, connection);
OdbcParameter param = command.Parameters.Add("@searchPattern", OdbcType.VarChar, 255);
param.Value = "%" + searchTerm + "%";
```

## Explanation

The original code constructs the SQL query by concatenating the untrusted `searchTerm` directly into the query string. An attacker could inject SQL fragments by supplying input like `%' OR '1'='1` to manipulate query logic and bypass the WHERE clause entirely, returning all rows or exposing unauthorized data.

The fix replaces string concatenation with a parameterized query using ODBC parameter binding. The `?` placeholder reserves a position for a parameter value, and `OdbcParameter.Add()` with an explicit `OdbcType.VarChar` binds the user input as data, not as executable SQL. The wildcard characters (`%`) are included in the parameter value so the LIKE pattern is preserved while the searchTerm content is safely escaped. Parameter binding ensures the value is always treated as literal data regardless of its content.

## Behaviour changes

None. The parameterized query preserves the original query semantics and wildcard matching behavior. The sink contract (`ExecuteReader()` returns an `OdbcDataReader`) is unchanged. The `OdbcParameter.Add()` method returns the parameter object, which is assigned immediately without altering the subsequent call to `ExecuteReader()` or the result processing loop.
