## Verdict

Confirmed SQL Injection. Line 28 in Case01B.java builds a SQL query by concatenating untrusted user input directly into a string, then executes it. The input flows from `request.getParameter("name")` in Case01A without validation or parameterization.

## Source

**Source:** `Case01A.java` line 15
```java
data = request.getParameter("name");
```

**Sink:** `Case01B.java` line 28
```java
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

The untrusted `data` parameter is passed to `Case01B.handleSink()` and concatenated directly into the SQL query string. An attacker can inject SQL syntax (e.g., `' OR '1'='1`) to manipulate query logic, bypass authentication, or extract unauthorized data.

## Fix

Replace the string-concatenated query with a parameterized query using `PreparedStatement`:

```java
public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
{
    Connection dbConnection = null;
    PreparedStatement preparedStatement = null;
    ResultSet resultSet = null;

    try
    {
        dbConnection = IO.getDBConnection();
        String query = "select * from users where name=?";
        preparedStatement = dbConnection.prepareStatement(query);
        preparedStatement.setString(1, data);
        resultSet = preparedStatement.executeQuery();

        IO.writeLine(resultSet.getRow()); 
    }
    catch (SQLException exceptSql)
    {
        IO.logger.log(Level.WARNING, "Error getting database connection", exceptSql);
    }
    finally
    {
        try
        {
            if (resultSet != null)
            {
                resultSet.close();
            }
        }
        catch (SQLException exceptSql)
        {
            IO.logger.log(Level.WARNING, "Error closing ResultSet", exceptSql);
        }

        try
        {
            if (preparedStatement != null)
            {
                preparedStatement.close();
            }
        }
        catch (SQLException exceptSql)
        {
            IO.logger.log(Level.WARNING, "Error closing Statement", exceptSql);
        }

        try
        {
            if (dbConnection != null)
            {
                dbConnection.close();
            }
        }
        catch (SQLException exceptSql)
        {
            IO.logger.log(Level.WARNING, "Error closing Connection", exceptSql);
        }
    }
}
```

**Changes:**
1. Replace `Statement sqlStatement` with `PreparedStatement preparedStatement`
2. Use `prepareStatement(query)` with a static SQL string containing a `?` placeholder for the value
3. Bind the user input using `setString(1, data)` - this ensures the input is always treated as data, never as SQL structure
4. Call `executeQuery()` without arguments (the statement is already prepared with the query and bound parameters)
5. Update the finally block to close `preparedStatement` instead of `sqlStatement`

## Explanation

Parameterized queries separate SQL structure from data values. The `?` placeholder marks where user input goes, and `setString()` binds the actual value through a separate channel. The database driver ensures the input is treated as data only - special characters like quotes and SQL keywords are escaped by the driver's prepared statement implementation, preventing the attacker from altering query syntax. This is the only reliable defence against SQL injection in Java; manual escaping is inconsistent and error-prone, and string concatenation is vulnerable regardless of later validation attempts.

## Behaviour changes

The query now processes user input safely through parameterization. Malicious input like `' OR '1'='1` is now treated as a literal string value in the `name` column search, not as SQL syntax. The result set size and query semantics remain unchanged for legitimate input - only injection attacks are prevented. No change to error handling, logging, or resource cleanup.
