## Verdict

Exploitable. The `data` parameter is concatenated directly into the SQL query string without parameterization or escaping, allowing an attacker to inject arbitrary SQL code.

## Source

The `data` parameter received by the `handleSink()` method in Case13B.java represents untrusted user input (originating from Case13A where it would typically come from request parameters in a real application).

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

The original code built the SQL query through string concatenation, concatenating the untrusted `data` parameter directly into the query string. This allows an attacker to inject SQL commands by providing input like `'; DROP TABLE users; --`. The fix uses `PreparedStatement` with parameterized queries: the SQL structure is defined separately from the data. The `?` placeholder marks where the parameter goes, and `setString(1, data)` binds the untrusted data as a value rather than as query structure. The database driver ensures the parameter is treated as data, not executable SQL, preventing injection regardless of the input content. This is the primary defence mechanism for SQL injection in JDBC.

## Behaviour changes

- Changed `Statement` type to `PreparedStatement` for safer parameterized query execution
- Split query execution into two steps: prepare (with `?` placeholder) then bind parameter with `setString(1, data)` before executing
- Modified `executeQuery()` call: original passed the concatenated SQL string as an argument; fixed version passes no string argument since the query is already prepared
- No other differences in control flow, error handling, resource management, or output behaviour

