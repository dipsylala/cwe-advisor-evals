## Verdict
CONFIRMED - SQL Injection via unsanitized string concatenation in SQL query construction.

## Source
User-controlled input from `request.getParameter("name")` in Case02A flows through Case02B and Case02C to Case02D.handleSink() where it is received as the `data` parameter.

## Fix
Replace `Statement` with `PreparedStatement` and use parameterized queries:

```java
public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
{
    Connection dbConnection = null;
    PreparedStatement sqlStatement = null;
    ResultSet resultSet = null;

    try
    {
        dbConnection = IO.getDBConnection();
        sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
        sqlStatement.setString(1, data);

        resultSet = sqlStatement.executeQuery();

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
            if (sqlStatement != null)
            {
                sqlStatement.close();
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

## Explanation
Line 28 concatenates user-controlled `data` directly into the SQL query string: `"select * from users where name='"+data+"'"`. This allows an attacker to inject arbitrary SQL by providing input like `' OR '1'='1` or `'; DROP TABLE users; --`, which would alter the query's logic or cause data loss.

The fix uses `PreparedStatement` with a parameterized query (`?` placeholder). The `setString(1, data)` method properly escapes the input according to SQL syntax rules, ensuring the value is always treated as literal data, never as executable SQL code. This is the standard defence against SQL injection in Java.

Key changes:
- `createStatement()` → `prepareStatement("select * from users where name=?")`
- `setString(1, data)` binds the user input safely as the first parameter
- `executeQuery(String)` → `executeQuery()` (no argument, since the query is already compiled)
- Declaration changed from `Statement` to `PreparedStatement` for type correctness
