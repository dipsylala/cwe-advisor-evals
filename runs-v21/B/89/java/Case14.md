## Verdict

Exploitable. The original vulnerable code concatenates untrusted user input directly into SQL query strings without parameterization, allowing an attacker to inject arbitrary SQL commands.

## Source

Case14A.java line 15: `data = request.getParameter("name")` retrieves untrusted HTTP parameter. This value is passed to Case14B.handleSink() at line 17 without validation.

The data flows through the `data` parameter to Case14B's handleSink() method, where it reaches the SQL execution sink at line 29.

## Fix

### File: Case14B.java

```java


package evalcases;
import testcasesupport.*;

import javax.servlet.http.*;

import java.sql.*;

import java.util.logging.Level;

public class Case14B
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
                IO.logger.log(Level.WARNING, "Error closing PreparedStatement", exceptSql);
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

The fix replaces SQL string concatenation with a parameterized query using `PreparedStatement` with `?` placeholders. The untrusted user input (`data`) is now bound to the query parameter using `setString(1, data)` rather than being embedded in the SQL string itself. This ensures the input is always treated as data, never as executable SQL code. The `PreparedStatement` API sends the query structure and parameter values to the database separately, so any special SQL characters in the data (such as single quotes or `OR 1=1`) are neutralized and treated as literal string values. This is the primary defense recommended by OWASP and the CWE-89 guidance.

## Behaviour changes

None. The fixed code preserves the original behavior: it queries the users table by name parameter and returns the same ResultSet. The executeQuery() method's return type and exception handling remain identical. The parameterization changes only the query construction mechanism, not the semantic operation of the code.
