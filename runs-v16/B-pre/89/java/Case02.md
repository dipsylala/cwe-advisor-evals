## Verdict

CONFIRMED - SQL Injection vulnerability via direct string concatenation of untrusted input into SQL query.

## Source

User-controlled input flows from `HttpServletRequest.getParameter("name")` (Case02A, line 15) through an unvalidated call chain (Case02B -> Case02C) to the vulnerable sink in Case02D.

## Fix

Replace line 28 of Case02D.java from:

```
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

To use a prepared statement with parameter binding:

```
PreparedStatement preparedStatement = dbConnection.prepareStatement("select * from users where name=?");
preparedStatement.setString(1, data);
resultSet = preparedStatement.executeQuery();
```

Additionally, update the finally block to close the prepared statement:
- Change line 24 from: `sqlStatement = dbConnection.createStatement();`
- To: `PreparedStatement preparedStatement = dbConnection.prepareStatement("select * from users where name=?");` (moved to after the try block starts)
- And replace the sqlStatement close block (lines 51-60) with:

```
try
{
    if (preparedStatement != null)
    {
        preparedStatement.close();
    }
}
catch (SQLException exceptSql)
{
    IO.logger.log(Level.WARNING, "Error closing PreparedStatement", exceptSql);
}
```

## Explanation

The vulnerability exists because `data` is concatenated directly into the SQL query string via `"... where name='"+data+"'"`. An attacker can supply input like `' OR '1'='1` to manipulate query logic and bypass intended restrictions.

The fix uses `PreparedStatement` with a `?` placeholder, which enforces a strict boundary between SQL query structure and user-supplied data. The `setString(1, data)` method binds the user input as a string value, not as executable SQL code. This guarantees the input cannot alter the query's structure regardless of its content, eliminating the injection vector.

`PreparedStatement` is the standard Java/JDBC mechanism for parameterized queries and is available on all JDBC drivers without additional dependencies.

## Behaviour changes

- **Query parsing**: The prepared statement is parsed once with the placeholder; parameter binding happens separately. This is more efficient for repeated queries but has negligible performance impact for one-shot queries.
- **Error handling**: `PreparedStatement` methods throw the same `SQLException` as `Statement`, so the existing catch block continues to function.
- **Result set behavior**: The `ResultSet` returned and its interface remain unchanged; no changes needed to result processing (line 30 onward).
- **Resource lifecycle**: The prepared statement must be closed in the finally block instead of the regular statement. The existing try-finally pattern is preserved.

