## Verdict

Confirmed. `Case02D.handleSink` builds a SQL query by concatenating the untrusted `data` value directly into the string passed to `Statement.executeQuery`, allowing SQL injection.

## Source

`Case02A.handle` reads the untrusted value from `request.getParameter("name")` and passes it unchanged through `Case02B.handleSink` and `Case02C.handleSink` into `Case02D.handleSink`, where it reaches the SQL sink at line 28 (`sqlStatement.executeQuery("select * from users where name='"+data+"'")`).

## Fix

### File: Case02D.java

```java


package evalcases;
import testcasesupport.*;

import javax.servlet.http.*;

import java.sql.*;

import java.util.logging.Level;

public class Case02D
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
            sqlStatement.setString(1, data);

            
            // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
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

The dangerous pattern was building a SQL string with `+` concatenation of user input and executing it with `Statement.executeQuery`, which lets any SQL metacharacters in `data` (e.g. `' OR '1'='1`) change the query's logic or structure. The fix replaces `Statement` with `PreparedStatement`, using a parameterized query (`... where name=?`) and binding `data` via `setString(1, data)`. The database driver then treats the bound value strictly as a literal string value for that parameter, never as SQL syntax, regardless of its content, which eliminates the injection while preserving the original query semantics. No other file in the call chain needed to change, since the vulnerability is entirely local to how `Case02D` constructs and executes the query.
