## Verdict
CONFIRMED - SQL Injection vulnerability via string concatenation at line 28. The `data` parameter is concatenated directly into the SQL query without parameterization.

## Source
Case13A.java, line 15: `data` parameter value is passed to Case13B.handleSink()
Case13B.java, line 14: `data` is received as a method parameter

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
The vulnerability was caused by concatenating the untrusted `data` parameter directly into the SQL query string using the `+` operator at line 28. An attacker controlling the `data` value could inject malicious SQL, such as `' OR '1'='1` to bypass authentication or extract unauthorized data.

The fix replaces `Statement.createStatement()` with `PreparedStatement.prepareStatement()` and uses a parameterized query with a `?` placeholder. The untrusted `data` value is then bound as a parameter using `setString(1, data)`, which ensures it is always treated as a literal string value, not as executable SQL code. The database driver handles all necessary escaping and quote handling automatically.

Changes made:
- Line 18: Changed declaration from `Statement sqlStatement` to `PreparedStatement sqlStatement`
- Line 24: Changed from `dbConnection.createStatement()` to `dbConnection.prepareStatement("select * from users where name=?")`
- Line 25: Added `sqlStatement.setString(1, data)` to bind the parameter
- Line 28: Changed from `sqlStatement.executeQuery("select * from users where name='"+data+"'")` to `sqlStatement.executeQuery()` (no SQL argument since it was already passed to prepareStatement)

## Behaviour changes
The functional behavior remains identical:
- The query still selects users matching the given name
- The result set is still returned and used the same way
- Error handling and resource cleanup (try-finally) remain unchanged

The only change is the mechanism: parameterized queries guarantee injection safety while preserving the original query semantics.
