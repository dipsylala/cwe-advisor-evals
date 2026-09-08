## Verdict

Exploitable

## Source

Untrusted user input from HTTP request parameter `name` extracted in Case03A.java line 15 via `request.getParameter("name")`, passed through intermediate handlers Case03B, Case03C, Case03D to Case03E where it reaches the vulnerable sink.

## Fix

### File: Case03E.java

```java


package evalcases;
import testcasesupport.*;

import javax.servlet.http.*;

import java.sql.*;

import java.util.logging.Level;

public class Case03E
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        Connection dbConnection = null;
        PreparedStatement sqlStatement = null;
        ResultSet resultSet = null;

        try
        {
            dbConnection = IO.getDBConnection();
            
            String query = "select * from users where name=?";
            sqlStatement = dbConnection.prepareStatement(query);
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
                IO.logger.log(Level.WARNING, "Error closing database connection", exceptSql);
            }
        }

    }
}
```

## Explanation

The vulnerable code built a SQL query by concatenating the untrusted `data` parameter directly into the SQL string: `"select * from users where name='"+data+"'"`. This allows an attacker to inject arbitrary SQL syntax—for example, passing `' OR '1'='1` as the name parameter would transform the query into `select * from users where name='' OR '1'='1'`, which would return all rows.

The fix replaces `Statement` with `PreparedStatement` and uses parameterized query syntax. The SQL query is now constructed with a `?` placeholder for the value position: `"select * from users where name=?"`. The untrusted `data` is bound separately using `setString(1, data)`, which ensures it is always treated as a literal value, never as SQL structure. This eliminates SQL injection regardless of what characters or keywords the `data` parameter contains.

## Behaviour changes

The variable `sqlStatement` type changed from `Statement` to `PreparedStatement`, which is a subtype that implements the same `Statement` interface and supports all the same method calls used in the finally block (`close()`). The closing logic remains functionally identical. The method used to execute the query (`executeQuery()`) is the same on both Statement and PreparedStatement, so the return type and behavior are unchanged. No changes to exception handling, resource cleanup, or output behavior.
