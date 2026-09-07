## Verdict

**Confirmed**: SQL Injection via direct string concatenation of unsanitized user input into a SQL query.

## Source

The vulnerability is on line 28 of Case13B.java:

```java
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

The `data` parameter is received from Case13A.handle() and concatenated directly into the SQL query string without any sanitization or parameterization. An attacker can inject arbitrary SQL by providing input such as `' or '1'='1` to bypass authentication or extract unauthorized data.

## Fix

### File: Case13B.java

```java


package evalcases;
import testcasesupport.*;

import javax.servlet.http.*;

import java.sql.*;

import java.util.logging.Level;

public class Case13B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        Connection dbConnection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try
        {
            dbConnection = IO.getDBConnection();
            preparedStatement = dbConnection.prepareStatement("select * from users where name = ?");
            preparedStatement.setString(1, data);

            
            // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
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
}
```

## Explanation

The fix replaces the vulnerable `Statement` with a `PreparedStatement` that uses parameterized queries. The key changes are:

1. **Replace `Statement` with `PreparedStatement`**: Use `dbConnection.prepareStatement()` instead of `dbConnection.createStatement()`.

2. **Use a placeholder**: The SQL query now uses `?` as a placeholder instead of concatenating the user input: `"select * from users where name = ?"` (note: also removed unnecessary quotes around the parameter).

3. **Set parameters safely**: The `preparedStatement.setString(1, data)` method binds the user input to the first parameter. The JDBC driver handles proper escaping and ensures the value is treated as data, not executable SQL code.

4. **Update resource management**: The finally block is updated to close the `preparedStatement` instead of `sqlStatement`, since we now use a prepared statement.

Parameterized queries are the standard defense against SQL injection in Java. They ensure that user-supplied values are always treated as data and cannot be interpreted as SQL commands, regardless of their content.

