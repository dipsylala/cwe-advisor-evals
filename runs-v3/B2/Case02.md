## Verdict

exploitable

## Source

Untrusted data enters at `Case02A.handle()` line 15: `data = request.getParameter("name")` - an attacker-controlled HTTP request parameter. The value is passed unchanged through a four-hop call chain with no validation, encoding, or reassignment at any hop:

1. `Case02A.java:15` - `data = request.getParameter("name")` (source)
2. `Case02A.java:17` - `(new Case02B()).handleSink(data, request, response)`
3. `Case02B.java:12` - `(new Case02C()).handleSink(data, request, response)`
4. `Case02C.java:12` - `(new Case02D()).handleSink(data, request, response)`
5. `Case02D.java:28` - `sqlStatement.executeQuery("select * from users where name='" + data + "'")` (sink)

`data` is concatenated directly into the SQL string inside a single-quoted literal, so a payload such as `' OR '1'='1` closes the literal and rewrites the `WHERE` clause; `'; DROP TABLE users; --` is available where the driver permits stacked statements. Nothing on the path constrains the value.

Sink contract as it currently stands: the call returns a `ResultSet` whose only use is `IO.writeLine(resultSet.getRow())` on line 30 - the row data itself is discarded. `createStatement()` is called with no arguments, taking the JDBC defaults (`TYPE_FORWARD_ONLY`, `CONCUR_READ_ONLY`, default holdability). On failure it throws `SQLException`, caught on line 32 and logged at `Level.WARNING`, leaving `resultSet` null for the `finally` block to skip.

## Fix

Complete fixed `Case02D.java`:

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

The changed lines, in isolation:

```java
// before
Statement sqlStatement = null;
...
sqlStatement = dbConnection.createStatement();
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");

// after
PreparedStatement sqlStatement = null;
...
sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
sqlStatement.setString(1, data);
resultSet = sqlStatement.executeQuery();
```

## Explanation

The query is now a fixed SQL string with a `?` placeholder in the position that previously held the concatenated value, and the untrusted `name` parameter is bound through `setString(1, data)` rather than spliced into the statement text. Because the statement is parsed before the parameter is supplied, the driver can only treat the bound value as a literal string operand of the `name=` comparison - quotes, semicolons, comment markers and SQL keywords inside it are matched as characters of the searched-for name and can no longer alter the query's structure. The variable's declared type moves from `Statement` to `PreparedStatement` so the parameterised API is reachable; `PreparedStatement` extends `Statement`, so the existing null checks and `close()` calls in the `finally` block continue to work unchanged. Escaping or filtering the input was rejected in favour of parameterisation: it leaves the query structure dependent on the input and fails differently in quoted and unquoted contexts, whereas binding removes the data/code boundary problem entirely.

## Behaviour changes

- **Statement variable type (`Statement` -> `PreparedStatement`)** - required to call `setString()`; `PreparedStatement` is a subinterface of `Statement`, so the `finally` block's `close()` and null handling are unaffected. No other code in the case chain references this local.
- **No-argument `executeQuery()` replaces the string overload** - required by the parameterised form; it executes the same statement and returns the same `ResultSet`, which the caller still consumes only as `resultSet.getRow()`. Nothing previously discarded is now surfaced.
- **Cursor defaults preserved** - `prepareStatement(String)` uses the same JDBC defaults as `createStatement()` (`TYPE_FORWARD_ONLY`, `CONCUR_READ_ONLY`, default holdability), so no implicit argument has been silently widened.
- **Failure behaviour preserved, with one shift in origin point** - a malformed-SQL or connection failure can now be raised by `prepareStatement()` rather than by `executeQuery()`. Both calls sit inside the same `try`, both throw `SQLException`, and the existing catch logs it identically at `Level.WARNING` with `resultSet` left null, so observable behaviour is unchanged.
- **Matching semantics for hostile input** - a `name` value containing a quote is now matched literally instead of altering the query. This is the intended effect of the fix, not an incidental change; a legitimate name such as `O'Brien` now matches correctly where it previously produced a syntax error.
- **Confidence** - high; the full source-to-sink path is present in the case files and each hop passes the value unmodified.
- **Dependency changes** - none; the fix uses JDBC's built-in `PreparedStatement`, so no manifest or library version change is required.
- **Otherwise none** - the log messages, `IO.writeLine(resultSet.getRow())`, the resource-cleanup sequence, the method signature and the imports (`java.sql.*` already covers `PreparedStatement`) are untouched.
- **Assumptions** - `IO.getDBConnection()` returns a standard JDBC `java.sql.Connection`, as its use with `createStatement()`/`executeQuery()` indicates; `testcasesupport.IO` was not on the read path for this finding. If it returns a wrapper without `prepareStatement()`, the binding call would need routing through whatever equivalent that wrapper exposes.
