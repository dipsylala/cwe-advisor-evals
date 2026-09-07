## Verdict
SQL Injection vulnerability confirmed. The query on line 28 concatenates untrusted user input directly into the SQL string, allowing an attacker to inject arbitrary SQL code.

## Source
**File:** Case02D.java (line 28)
**Sink:** `sqlStatement.executeQuery("select * from users where name='"+data+"'")`
**Data flow:** HTTP request parameter "name" → Case02A → Case02B → Case02C → Case02D.handleSink() → SQL query execution

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
The vulnerability was introduced by using string concatenation to build the SQL query. This allows an attacker to supply input like `' OR '1'='1` to manipulate the query logic or extract data.

The fix uses `PreparedStatement` with parameterized queries:
- **Line 24:** Changed from `createStatement()` to `prepareStatement()` with a placeholder `?` for the parameter
- **Line 18:** Changed the variable type from `Statement` to `PreparedStatement`
- **Line 25:** Added `setString(1, data)` to safely bind the user-supplied value to the first parameter
- **Line 28:** Changed from concatenating the parameter into the query string to calling `executeQuery()` with no arguments, since the query is already prepared with the parameter safely bound

This approach ensures that user input is treated as data, not code, preventing SQL injection attacks. The JDBC driver handles the proper escaping and encoding of the parameter value.
