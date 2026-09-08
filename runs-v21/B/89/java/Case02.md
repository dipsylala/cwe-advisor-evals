## Verdict

SQL Injection vulnerability confirmed. Untrusted user input from `HttpServletRequest.getParameter("name")` is concatenated directly into a SQL query string without parameterization, allowing an attacker to manipulate query logic through special characters like quotes and SQL keywords.

## Source

Entry point: Case02A line 15 - `data = request.getParameter("name");`

Data flows through:
- Case02A → Case02B.handleSink() (line 17)
- Case02B → Case02C.handleSink() (line 12)
- Case02C → Case02D.handleSink() (line 12)
- Case02D line 28: `resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");`

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

The fix eliminates SQL injection by replacing string concatenation with parameterized queries. Instead of building the SQL string dynamically with untrusted data (`"select * from users where name='"+data+"'"`), the query uses a `?` placeholder for the name value. The `PreparedStatement.setString(1, data)` call binds the user input as a data parameter, not as query structure. The database driver treats the bound value as literal data regardless of its content—special characters like quotes, semicolons, or SQL keywords are escaped automatically and cannot alter the query's logic. This eliminates the injection vector while preserving the original functionality of querying for users by name.

## Behaviour changes

- **Sink type**: Changed from `Statement.executeQuery(String)` to `PreparedStatement.executeQuery()`
- **Parameter handling**: User input no longer appears in the SQL query string; instead it is bound as a data parameter via `setString(1, data)`
- **Query structure**: SQL template is fixed (`"select * from users where name=?"`) and cannot be manipulated by input
- **Result handling**: The `ResultSet` returned and its usage (`.getRow()`) remain identical
- **Exception handling**: Identical catch and finally blocks; exception types remain unchanged
- **Resource cleanup**: Connection, statement, and result set cleanup remains identical
- **API usage**: `java.sql.PreparedStatement` is a standard JDBC API; no external dependencies added beyond what was already required

