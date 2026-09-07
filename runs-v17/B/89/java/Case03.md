## Verdict

Exploitable. The `data` parameter (line 14) flows untrusted from the HTTP request handler into line 28's `executeQuery()` call via string concatenation, allowing an attacker to inject arbitrary SQL syntax. An input like `' OR '1'='1` transforms the intended query into a tautology that bypasses the WHERE clause.

## Source

The `data` parameter passed to `handleSink()` at line 14 originates from the HTTP request context (`HttpServletRequest` parameter) and is attacker-controlled. No validation occurs before use.

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

The fix replaces the concatenated query with a `PreparedStatement` that uses a parameterized placeholder (`?`). The untrusted `data` value is bound separately via `setString(1, data)`, ensuring the parameter is treated as literal data rather than executable SQL syntax. This prevents the attacker from injecting query logic—any metacharacters in `data` are escaped by the JDBC driver before reaching the database parser. The variable type is changed from `Statement` to `PreparedStatement` to reflect the prepared statement's more specific contract.

## Behaviour changes

- Variable `sqlStatement` type changed from `Statement` to `PreparedStatement` (more specific interface)
- `createStatement()` replaced with `prepareStatement("select * from users where name=?")` to bind the query structure once rather than rebuild it from concatenation
- `setString(1, data)` call added to bind the untrusted input as a parameter
- `executeQuery()` now called without arguments (the query and bindings are already set on the prepared statement)

All other behavior is preserved: the method signature, exception handling, resource cleanup, and return value remain unchanged.
