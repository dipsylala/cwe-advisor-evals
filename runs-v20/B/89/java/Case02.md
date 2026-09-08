## Verdict

Exploitable. CWE-89 (SQL Injection), confidence: high.

- Location: `Case02D.java`, line 28, `sqlStatement.executeQuery("select * from users where name='"+data+"'")`
- Source: `request.getParameter("name")` in `Case02A.handle` (line 15)
- Sink: `Statement.executeQuery()` in `Case02D.handleSink` (line 28)

## Source

`request.getParameter("name")` in `Case02A.handle`. This is an `HttpServletRequest` parameter, fully attacker-controlled with no length, character, or format restrictions.

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

`data` reaches `Case02D.handleSink` unmodified from `request.getParameter("name")` through `Case02A` -> `Case02B` -> `Case02C`, with no validation or escaping anywhere along the chain, so the finding is exploitable as reported. The fix replaces the `Statement` built by concatenating `data` directly into the SQL text with a `PreparedStatement` using a `?` placeholder for the value position, and binds `data` with `setString(1, data)` so the JDBC driver sends it to the database as a literal value rather than as SQL text. `sqlStatement`'s declared type changes from `Statement` to `PreparedStatement`; the query is prepared once with the connection and executed with the no-argument `executeQuery()` overload, which is `PreparedStatement`'s bound-parameter form of the same call. Only the value position was parameterized because `data` occupies a value position (`name='...'`), not an identifier position - no allowlist substitution is needed here.

## Behaviour changes

- `sqlStatement`'s static type changes from `Statement` to `PreparedStatement`. `PreparedStatement` extends `Statement`, so the existing `sqlStatement.close()` call in the `finally` block still resolves and behaves identically.
- `executeQuery(String)` becomes the zero-argument `executeQuery()`; the query text itself is unchanged apart from substituting `?` for the concatenated value, so the returned `ResultSet` and its use (`resultSet.getRow()`, `resultSet.close()`) are unaffected.
- Error handling, logging, and resource-closing order in the `finally` block are untouched.
- No other file in the call chain (`Case02A`, `Case02B`, `Case02C`) required a change; `data` is still passed through unchanged, now safely bound rather than concatenated at the sink.
- Net effect: identical query semantics and identical result handling for legitimate input; a `name` value containing `'` or other SQL metacharacters is now treated as literal data instead of altering query structure.

Verification: the fixed file was compiled with `javac --release 17` against stub definitions of `testcasesupport.IO`, `testcasesupport.AbstractTestCaseServlet`, `javax.servlet.http.HttpServletRequest`, and `javax.servlet.http.HttpServletResponse` (the real servlet-api and support classes are not available in isolation from the case fixture) in a scratch directory outside the repository. It compiled with no errors or warnings. `PreparedStatement`, `Connection.prepareStatement(String)`, and `PreparedStatement.setString(int, String)` are all from `java.sql`, already imported via the file's existing `import java.sql.*;`.
