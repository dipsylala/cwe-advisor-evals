## Verdict

SQL Injection vulnerability confirmed. User-supplied input from `request.getParameter("name")` flows directly into a SQL query via string concatenation without parameterization.

## Source

Call chain:
- **Case01A.java, line 15**: `data = request.getParameter("name");` retrieves untrusted user input
- **Case01B.java, line 28**: Input concatenated directly into query string: `"select * from users where name='"+data+"'"`

The taint sink is `Statement.executeQuery()` with a dynamically constructed query string.

## Fix

Replace `Statement` with `PreparedStatement` to use parameterized queries:

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

Parameterized queries (PreparedStatement) separate SQL structure from data. The query template is compiled once, and user input is bound as a parameter using `setString()`, `setInt()`, etc. This treats the input as literal data, preventing any attacker-supplied SQL syntax from being interpreted as code.

Key changes:
- `dbConnection.createStatement()` → `dbConnection.prepareStatement("select * from users where name=?")` with a `?` placeholder for the parameter
- `sqlStatement.setString(1, data)` binds the user input safely to the first parameter
- `sqlStatement.executeQuery()` (no argument) executes the compiled parameterized query

This approach is native to JDBC and requires no additional libraries.
