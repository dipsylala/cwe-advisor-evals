## Verdict

Confirmed SQL Injection via ODBC. Untrusted `searchTerm` parameter is concatenated directly into the SQL query string at line 25, allowing an attacker to inject arbitrary SQL by providing crafted input such as `' OR '1'='1%`. The malicious SQL reaches the sink at line 29 (`ExecuteReader()`), which executes the attacker-controlled query.

## Source

- **Input source**: `searchTerm` parameter to `SearchPartsByDescription()` at line 17 — attacker-controlled
- **Data path**: Line 25 concatenates `searchTerm` into SQL string using `+` operator → line 26 passes SQL to `OdbcCommand` → line 29 executes via `ExecuteReader()`
- **Sink**: `OdbcCommand.ExecuteReader()` at line 29

## Fix

Replace the concatenated SQL with a parameterized query. Change lines 25–26 from:

```csharp
string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE '%" + searchTerm + "%'";
var command = new OdbcCommand(sql, connection);
```

to:

```csharp
string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE ?";
var command = new OdbcCommand(sql, connection);
command.Parameters.Add("searchTerm", OdbcType.NVarChar).Value = "%" + searchTerm + "%";
```

## Explanation

Parameterized queries separate the query structure from the data values. The ODBC placeholder `?` is replaced by the database driver with the actual parameter value, but the value is always treated as data, never as executable SQL. Even if `searchTerm` contains SQL metacharacters or logic operators (e.g., `' OR '1'='1`), they are passed as literal string data to the `LIKE` clause and cannot manipulate the query structure. The wildcard characters `%` remain in the parameter value to preserve the partial-match search functionality of the original query.

## Behaviour changes

- The query now uses a parameter placeholder instead of string concatenation, eliminating the injection vector.
- The `LIKE` clause functionality is preserved: the `%` wildcards are now part of the bound parameter value rather than the query template.
- Query execution is deferred until the database driver receives and validates the parameter.
- The `OdbcType.NVarChar` type declaration ensures the parameter is treated as a string in all contexts.
