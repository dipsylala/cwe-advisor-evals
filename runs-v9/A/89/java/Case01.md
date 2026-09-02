## Verdict

Confirmed. `data`, built from unsanitized, attacker-controlled input, is concatenated directly into a SQL string that is executed via `Statement.executeQuery`. An attacker can alter the query's logic or extract data from other rows/tables.

## Source

`Case01A.handle` reads the untrusted value from the HTTP request:

```java
data = request.getParameter("name");
```

This value is passed unmodified into `Case01B.handleSink(data, request, response)`.

## Fix

Replace the `Statement` with a `PreparedStatement` that binds `data` as a parameter instead of concatenating it into the SQL text:

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

The original code builds the query by string concatenation:

```java
sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

Because `data` comes straight from `request.getParameter("name")` with no validation or encoding, any single quote or SQL syntax the caller supplies becomes part of the query the database executes. A value such as `' OR '1'='1` turns the `WHERE` clause into a tautology, and more elaborate payloads (`UNION SELECT`, stacked queries, etc., depending on the driver/DB) can be used to read unrelated tables or bypass the intended filter entirely.

`PreparedStatement` with a parameterized placeholder (`?`) fixes this at the mechanism level: the query text is compiled and sent to the database once, and `data` is transmitted separately as a bind parameter via `setString`. The database driver never re-parses `data` as SQL syntax, so quotes, comments, or keywords inside it cannot change the query's structure - they can only ever be matched as a literal value for the `name` column. This is a drop-in replacement here: `createStatement()`/`executeQuery(sql)` becomes `prepareStatement(sql)` with a `?` placeholder plus `setString(1, data)`, and `executeQuery()` is called with no arguments since the SQL and parameter were already supplied. The rest of the resource-cleanup logic (closing `resultSet`, the statement, and the connection in `finally`) is unaffected and needs no change beyond the declared type of `sqlStatement`.

No additional input validation is required for this fix to be sound; parameterization removes the injection vector regardless of what characters `data` contains. If the application has a business reason to further constrain `name` (e.g., length or character-set limits), that can be layered on separately, but it is not what closes this SQL injection finding.
