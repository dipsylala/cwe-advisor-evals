## Verdict

exploitable

## Source

`Case03A.handle()` reads untrusted input via `request.getParameter("name")` and passes it, unchanged, through `Case03B.handleSink()` -> `Case03C.handleSink()` -> `Case03D.handleSink()` -> `Case03E.handleSink()` as the `data` parameter. None of the intermediate hops validate, escape, or otherwise constrain the value.

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

The sink built a SQL string by concatenating the untrusted `data` value directly into the query text (`"select * from users where name='"+data+"'"`), so an attacker-controlled value such as `' OR '1'='1` alters the query's logic rather than being treated as a literal name. The fix replaces the ad-hoc `Statement` with a `PreparedStatement` built from a static query containing a `?` placeholder for the value position, and binds `data` with `setString(1, data)` instead of splicing it into the SQL text. The JDBC driver sends the value as data in a separate channel from the query structure, so it can no longer change the statement's logic regardless of its content. No allowlist is needed here because the placeholder sits in a value position (a `WHERE` comparison), not an identifier or clause position.

## Behaviour changes

- `Statement sqlStatement` -> `PreparedStatement sqlStatement`: required to use bound parameters; the finally-block close/error-handling logic for `sqlStatement` is unchanged since `PreparedStatement` extends `Statement` and exposes the same `close()` contract.
- `sqlStatement.executeQuery("select * from users where name='"+data+"'")` -> `sqlStatement.executeQuery()` on a pre-built `PreparedStatement` with `setString(1, data)`: the query text, the returned `ResultSet` type, and the caller's use of `resultSet.getRow()` are unchanged - only how the value reaches the query changed.
- No change to error handling, logging, resource-closing order, method signature, or the values returned/thrown to callers Case03A-D.
- none beyond the above; the sink's returns, discards, implicit arguments, and failure behaviour are all preserved.

## Verification

Compiled with `javac --release 17` against the real `Case03A.java`-`Case03D.java` (copied unmodified) and the repository's `testcasesupport.IO` / `testcasesupport.AbstractTestCaseServlet` stubs, using `javax.servlet-api-4.0.1.jar` on the classpath, from a scratch directory outside the case fixture. Compilation succeeded with no errors or warnings (an unrelated ambiguity against JDK 26's new `java.lang.IO` preview class was resolved by targeting `--release 17`, which matches the servlet-era API surface these stubs target and does not affect the fix itself).

## Assumptions

- Assumed the finding's data flow is exactly the caller-provided chain (A -> B -> C -> D -> E) with no additional callers, since only these five files exist in the case directory.
- Assumed the target database driver's `PreparedStatement` implementation supports standard `?` placeholder binding (true for all mainstream JDBC drivers); no driver-specific behavior was otherwise assumed.
