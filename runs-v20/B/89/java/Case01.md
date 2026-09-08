## Verdict

Exploitable. CWE-89 (SQL Injection).

## Source

`Case01A.handle()` reads an attacker-controlled HTTP parameter: `data = request.getParameter("name")` (Case01A.java, line 15), then passes it unmodified into `Case01B.handleSink(data, request, response)` (Case01A.java, line 17). No validation or encoding is applied between the source and the call.

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

The sink at line 28 built the SQL statement by directly concatenating the untrusted `data` value into a string literal (`"select * from users where name='"+data+"'"`) and ran it through `Statement.executeQuery()`, so any quote or SQL metacharacter in the `name` request parameter is interpreted as query syntax rather than as data. The fix replaces `Statement` with `PreparedStatement`: the query text is now the static literal `select * from users where name=?`, and the untrusted value is bound afterward with `setString(1, data)`. The JDBC driver sends the value as a parameter, not as part of the SQL text, so it can no longer alter the query's structure regardless of its content. This is the primary defence named in the CWE-89 Java guidance (parameterized queries via `PreparedStatement`) and requires no additional library.

## Behaviour changes

- `sqlStatement`'s declared type changes from `Statement` to `PreparedStatement`. Both expose `.close()`, so the `finally` block's cleanup logic is unaffected.
- The query is now built once via `dbConnection.prepareStatement(sql)` instead of `dbConnection.createStatement()` followed by `sqlStatement.executeQuery(sql)`; the executed SQL text and the effective query semantics (same table, same `WHERE name = <value>` filter) are unchanged for any input that does not contain SQL metacharacters. Both `createStatement()` and `prepareStatement(String)` use the same implicit defaults (`TYPE_FORWARD_ONLY`, `CONCUR_READ_ONLY`), so the returned `ResultSet`'s scrolling/concurrency behavior is identical.
- `resultSet.getRow()`'s return value and `IO.writeLine()`'s output are unchanged in shape; the fix does not alter what is returned, discarded, or logged.
- Exception handling, logging, and the try/finally resource-cleanup order are untouched.
- Net effect: for legitimate `name` values, the query and its results are identical to before. For a `name` value carrying a quote or other SQL metacharacter, the value is now treated strictly as data instead of being interpreted as query syntax - this is the intended closure of the weakness, not an incidental behavior change.

## Verification

Compiled the fixed `Case01B.java` together with the unmodified `Case01A.java` against minimal local stand-ins for `javax.servlet.http.HttpServletRequest`/`HttpServletResponse` and `testcasesupport.IO`/`AbstractTestCaseServlet` (the real definitions are outside the two-file call chain and not part of this fix) using `javac --release 17`. Compilation succeeded with no errors or warnings. (`--release 17` was used only to avoid an unrelated name collision between the stub `IO` class and JDK 26's preview `java.lang.IO`; it does not affect the fix itself.) Every name the fix introduces - `PreparedStatement`, `Connection.prepareStatement(String)`, `PreparedStatement.setString(int, String)`, `PreparedStatement.executeQuery()` - is part of `java.sql`, already imported via the file's existing `import java.sql.*;`.

## Assumptions

None. The finding, source, and sink were unambiguous from the two-file call chain.
