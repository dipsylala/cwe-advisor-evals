## Verdict
Exploitable SQL injection vulnerability confirmed. Untrusted user input from HTTP parameter `name` flows through a four-method call chain (Case02A → Case02B → Case02C → Case02D) and is concatenated directly into a SQL query at the sink without parameterization. The vulnerability allows an attacker to manipulate SQL query logic, access unauthorized data, or execute administrative operations.

## Source
- **Entry point**: Case02A line 15: `data = request.getParameter("name")` - untrusted user input from HTTP request parameter
- **Call chain**:
  - Case02A.handle() passes data to Case02B.handleSink()
  - Case02B.handleSink() passes data to Case02C.handleSink()
  - Case02C.handleSink() passes data to Case02D.handleSink()
- **Sink**: Case02D line 28: `sqlStatement.executeQuery("select * from users where name='"+data+"'")` - concatenation of untrusted data into SQL string

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


            // CWE-89 fix: Use PreparedStatement with parameterized query
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
The fix eliminates SQL injection by replacing string concatenation with a `PreparedStatement` using parameterized queries. The original code built the SQL query dynamically by concatenating the untrusted `data` parameter directly into the query string. An attacker could inject SQL metacharacters (e.g., `' OR '1'='1`) to alter query logic.

The fixed code uses `dbConnection.prepareStatement()` with a `?` placeholder, then binds the untrusted input via `sqlStatement.setString(1, data)`. This ensures the database driver treats the input as a data value, not as executable SQL code. The `?` placeholder is a positional parameter marker that the JDBC driver substitutes at execution time, preventing injection regardless of the input content.

Key changes:
1. Line 18: Changed `Statement` to `PreparedStatement`
2. Lines 22-23: Replaced `createStatement()` with `prepareStatement()` containing a parameterized query, and bound the user input using `setString()`
3. Line 27: Removed the SQL string argument from `executeQuery()` (PreparedStatement already has the query)

## Behaviour changes
- **Query execution**: The query still executes and returns the same `ResultSet` containing matching user records. The functional behaviour (filtering by name) is preserved.
- **Input handling**: Special SQL characters in the user input (quotes, semicolons, SQL keywords) are now treated as literal string data rather than query syntax.
- **Performance**: Prepared statements can be reused across multiple invocations with different parameter values, though this particular fix does not leverage that. There is negligible performance difference for a single execution.
- **Error handling**: SQLException handling is unchanged. Both the original and fixed code catch and log SQL exceptions identically.
- **Resource cleanup**: The finally block closes resources in the same order. PreparedStatement is a subtype of Statement, so the close() call remains compatible.
