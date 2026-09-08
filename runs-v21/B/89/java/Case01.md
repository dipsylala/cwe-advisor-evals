## Verdict

**Confirmed SQL Injection** - Untrusted user input from `request.getParameter("name")` in Case01A is concatenated into a SQL query string at Case01B.java line 28, allowing attackers to manipulate query logic by injecting SQL metacharacters.

## Source

| Component | Details |
|-----------|---------|
| Source entry point | Case01A.java, line 15: `request.getParameter("name")` |
| Tainted variable | `data` parameter passed to `Case01B.handleSink()` |
| Sink location | Case01B.java, line 28: `sqlStatement.executeQuery("select * from users where name='"+data+"'")` |
| Injection vector | String concatenation into SQL WHERE clause |

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

The fix replaces string concatenation with a parameterized query using JDBC's `PreparedStatement`. The key changes are:

1. **Type change** (line 18): `Statement` → `PreparedStatement` - the prepared statement type enforces parameterized query semantics
2. **Query preparation** (line 24): `createStatement()` → `prepareStatement("select * from users where name=?")` - the SQL query skeleton is now compiled once with a placeholder (`?`) in the value position, preventing the database from interpreting subsequent input as query structure
3. **Parameter binding** (line 25): `sqlStatement.setString(1, data)` - the untrusted input is now bound as data to the first placeholder, not concatenated into the SQL string
4. **Query execution** (line 28): `executeQuery("...")` → `executeQuery()` with no argument - the query structure is fixed, and only the bound parameter value varies

This closes the SQL Injection vulnerability because the database parser always treats the bound parameter as a string value, never as executable SQL. Injection metacharacters like `' OR '1'='1` are escaped automatically by the JDBC driver.

## Behaviour changes

- **No breaking changes**: The `ResultSet` return value and exception handling are preserved. The caller's code at line 30 (`resultSet.getRow()`) and all catch/finally blocks remain functional.
- **Query semantics unchanged**: The SQL query still returns the same result set for valid names; only the injection attack surface is eliminated.
- **Resource cleanup unchanged**: All existing resource cleanup in the finally block (ResultSet, Statement, Connection closes) continues to work correctly with `PreparedStatement`, which extends `Statement`.
