## Verdict

Confirmed. SQL Injection vulnerability via string concatenation in dynamic SQL query construction. Untrusted user input from `request.getParameter("name")` is concatenated directly into an SQL query string, allowing attackers to inject malicious SQL commands.

## Source

Case01A.java line 15: `data = request.getParameter("name");` - attacker-controlled input
Case01B.java line 28: `sqlStatement.executeQuery("select * from users where name='"+data+"'");` - sink where injection occurs

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
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try
        {
            dbConnection = IO.getDBConnection();
            
            // Use PreparedStatement with parameterized query
            preparedStatement = dbConnection.prepareStatement("select * from users where name=?");
            preparedStatement.setString(1, data);
            resultSet = preparedStatement.executeQuery();

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
                if (preparedStatement != null)
                {
                    preparedStatement.close();
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

The vulnerability is eliminated by replacing string concatenation with a `PreparedStatement` that uses parameterized queries. The fix changes three key elements: (1) the SQL string now contains a `?` placeholder instead of concatenating the user input directly; (2) the variable type changes from `Statement` to `PreparedStatement`, which separates query structure from data values; and (3) the untrusted `data` parameter is bound as a string value using `setString(1, data)`, which ensures it is always treated as data, never as executable SQL code.

The JDBC driver automatically escapes and quotes the bound parameter appropriately for the database, making injection impossible. An attacker providing input like `' OR '1'='1` will have it treated as a literal string value to match against the `name` column, not as SQL logic to execute.

## Behaviour changes

The fix preserves the original behavior: the query executes with the same logic, returns the same `ResultSet`, and uses the same error handling and resource cleanup. The only change is in how the SQL query is constructed: it now uses parameterized queries instead of string concatenation, which prevents SQL injection while maintaining functional equivalence.
