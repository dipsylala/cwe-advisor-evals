## Verdict

exploitable

## Source

`searchTerm` parameter in `SearchPartsByDescription(string searchTerm)` method (line 17). This is untrusted user input passed directly into SQL query construction.

## Fix

**Vulnerable code (line 25):**
```csharp
string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE '%" + searchTerm + "%'";
var command = new OdbcCommand(sql, connection);
```

**Fixed code:**
```csharp
string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE ?";
var command = new OdbcCommand(sql, connection);
command.Parameters.AddWithValue("@searchTerm", "%" + searchTerm + "%");
```

## Explanation

The vulnerability exists because `searchTerm` is concatenated directly into the SQL query string on line 25 without parameterization. An attacker can inject SQL metacharacters (e.g., `' OR '1'='1`) to manipulate query logic. The fix replaces string concatenation with parameterized queries using `OdbcCommand.Parameters.AddWithValue()`. The `?` placeholder tells the ODBC driver to treat the bound parameter value strictly as data, not as executable SQL code. The wildcard pattern (`%` + `searchTerm` + `%`) is constructed in C# before binding, ensuring only the user's search term data is parameterized. This prevents SQL injection while maintaining the intended LIKE search functionality.

## Behaviour changes

None. The parameterized query executes the same search logic with identical results. The sink contract (`OdbcCommand.ExecuteReader()`) remains unchanged: the method still returns an `OdbcDataReader` that the caller iterates over exactly as before. Parameter binding imposes no change to exception behavior, return values, or output production.

