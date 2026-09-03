## Verdict

SQL Injection via unparameterized query construction. The `ownerName` route parameter is concatenated into the SQL query string using `string.Format()` at line 30, then executed at line 33. An attacker can manipulate the query by supplying special characters (e.g., `' OR '1'='1`) to bypass the WHERE clause and delete all records.

## Source

Route parameter `ownerName` (line 21) flows directly into string interpolation at line 30:
```
command.CommandText = string.Format("DELETE FROM widgets WHERE owner = '{0}'", ownerName);
```

No validation or parameterization occurs before the value is concatenated into the SQL string.

## Fix

Replace the concatenated SQL with a parameterized query:

```csharp
command.CommandText = "DELETE FROM widgets WHERE owner = @ownerName";
command.Parameters.Add("@ownerName", SqlDbType.NVarChar).Value = ownerName;
```

The parameterized approach ensures `ownerName` is always treated as data, not as executable SQL code. The `@ownerName` placeholder is bound to the parameter value via `Parameters.Add()` with an explicit `SqlDbType`, preventing query structure manipulation.

## Explanation

The original code uses `string.Format()` to build a SQL query by concatenating the user-supplied `ownerName` directly into the query string. This violates CWE-89's primary defense: never embed untrusted input directly into SQL.

The fix applies parameterization (prepared statement semantics) via `SqlCommand.Parameters`. The parameter placeholder `@ownerName` stands in for the data value in the query template, and the actual value is bound separately via the `Parameters` collection. The database driver then treats the bound value purely as data, not as SQL structure, eliminating injection.

The `SqlDbType.NVarChar` type declaration is explicit rather than inferred (avoiding `AddWithValue`), and the size argument is omitted for `NVarChar` (variable-length) because no truncation is desired—the database will validate the actual size constraints if any.

## Behaviour changes

- Functional behavior is unchanged: the DELETE query still filters by the `owner` column and returns the same row count.
- SQL injection attacks via special characters in `ownerName` are now neutralized; the attacker cannot manipulate query structure.
- If the `ownerName` value contains SQL metacharacters (e.g., `'`, `--`, `/*`), they are now treated as literal string data rather than query syntax.
- Performance is identical or slightly improved (parameterized queries may benefit from query plan caching).
