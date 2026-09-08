## Verdict

The SQL injection vulnerability on line 28 of Case01B.java is confirmed. User-controlled input (`data` parameter) is concatenated directly into a SQL query string without parameterization or sanitization, allowing attackers to inject arbitrary SQL code.

## Source

The vulnerability chain:
1. **Case01A.java:15**: Untrusted input from HTTP request parameter `name`
2. **Case01A.java:17**: Input passed to Case01B's `handleSink()` method as `data` parameter
3. **Case01B.java:28**: Input concatenated directly into SQL query using string concatenation

```java
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

An attacker can craft input like `' OR '1'='1` to bypass authentication or extract sensitive data.

## Fix

### File: Case01B.java

```java


package evalcases;
import testcasesupport.*;

import javax.servlet.http.*;

import java.sql.*;

import java.util.logging.Level;

public class Case01B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        Connection dbConnection = null;
        PreparedStatement sqlStatement = null;
        ResultSet resultSet = null;

        try
        {
            dbConnection = IO.getDBConnection();
            sqlStatement = dbConnection.prepareStatement("select * from users where name=?");

            
            // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
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
}
```

## Explanation

The fix uses **parameterized queries** (prepared statements) instead of string concatenation:

1. **Change Statement to PreparedStatement**: Replace `dbConnection.createStatement()` with `dbConnection.prepareStatement()` that accepts a SQL template with a placeholder (`?`).

2. **Bind parameter safely**: Use `sqlStatement.setString(1, data)` to bind the user-supplied value as a parameter. The JDBC driver handles escaping and ensures the value is treated as data, not executable SQL.

3. **Separate query logic from data**: The SQL structure is fixed and cannot be altered by input. Only the data values change, eliminating injection vectors.

This approach is the standard defence against SQL injection in Java and ensures user input cannot modify query structure or execution semantics.
