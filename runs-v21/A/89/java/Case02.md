## Verdict

Confirmed SQL Injection vulnerability at Case02D.java line 28. The `data` parameter is unsanitized and concatenated directly into the SQL query string, allowing attackers to inject arbitrary SQL commands.

## Source

Case02A gets untrusted user input from the HTTP request parameter "name" and passes it through the call chain (Case02B → Case02C → Case02D). Case02D.java line 28 directly concatenates this input into a SQL query without parameterization:

```
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

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

            
            // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
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

The vulnerability stems from using string concatenation to build SQL queries. The fix uses parameterized queries with `PreparedStatement`:

1. Changed `Statement` to `PreparedStatement` on line 18 and line 24
2. Use `prepareStatement()` with a `?` placeholder for the user-supplied parameter
3. Call `setString(1, data)` to safely bind the parameter, which automatically escapes and ensures the data is treated as a literal value, not executable SQL code
4. Call `executeQuery()` without arguments after the parameter is bound

This approach prevents SQL injection because the database driver treats parameterized values as data, not SQL syntax. Any quotes or SQL metacharacters in `data` will be properly escaped and cannot alter the query structure.

