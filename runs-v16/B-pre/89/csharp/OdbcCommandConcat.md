## Verdict

Exploitable.

## Source

`searchTerm` parameter - user-controlled input passed to `SearchPartsByDescription()`.

## Fix

**Vulnerable code:**
```csharp
string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE '%" + searchTerm + "%'";
var command = new OdbcCommand(sql, connection);

using (OdbcDataReader reader = command.ExecuteReader())
{
    // Process results
}
```

**Fixed code:**
```csharp
string sql = "SELECT PartNumber, Description, WarehouseCode FROM Parts WHERE Description LIKE ?";
var command = new OdbcCommand(sql, connection);
command.Parameters.Add("@searchTerm", OdbcType.VarChar).Value = "%" + searchTerm + "%";

using (OdbcDataReader reader = command.ExecuteReader())
{
    // Process results
}
```

## Explanation

The original code concatenates untrusted `searchTerm` directly into the SQL query string, allowing attackers to inject SQL metacharacters (e.g., `' OR '1'='1`) to manipulate query logic. The fix replaces string concatenation with parameterized query execution: the SQL now uses a `?` parameter marker for the LIKE predicate, and `searchTerm` is passed separately to `OdbcCommand.Parameters.Add()` with explicit type `OdbcType.VarChar`, ensuring it is always treated as data, never as executable SQL. The LIKE wildcards remain in the parameter value because they are literal characters to be matched, not SQL structure.

## Behaviour changes

- ExecuteReader() now executes a prepared command with a bound parameter instead of a concatenated string.
- The database driver receives the LIKE pattern (including `%` wildcards) as a parameter value, not as part of the SQL query text.
- No change to return values, error handling, or result iteration logic.
