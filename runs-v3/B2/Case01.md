## Verdict

exploitable

## Source

Untrusted data enters at `Case01A.java:15`, where `handle()` reads an attacker-controlled HTTP request parameter with `request.getParameter("name")` and assigns it to `data`.

Path to the sink:

1. `Case01A.java:15` - `data = request.getParameter("name");` (source; no validation, no encoding, no length or character constraint).
2. `Case01A.java:17` - `(new Case01B()).handleSink(data, request, response);` passes the tainted value straight across the call boundary as the first argument.
3. `Case01B.java:14` - `handleSink(String data, ...)` receives the value unchanged; nothing between the parameter and the sink inspects, rewrites, or constrains it.
4. `Case01B.java:24` - a plain `Statement` is created via `dbConnection.createStatement()`.
5. `Case01B.java:28` (sink) - `sqlStatement.executeQuery("select * from users where name='" + data + "'")` concatenates the tainted value directly into the SQL text inside a single-quoted literal.

Because the value is interpolated into a quoted string literal with no escaping, a payload containing an apostrophe terminates the literal and the remainder is parsed as SQL structure. `' OR '1'='1` returns every row; `' UNION SELECT ...--` reaches arbitrary tables. The path is complete and unbroken from HTTP parameter to query execution.

Sink contract that the fix must preserve: the call returns a `ResultSet` assigned to `resultSet`, of which only `getRow()` is consumed and written out via `IO.writeLine`; the statement is created with the no-argument `createStatement()`, so the result set carries the driver defaults (forward-only, read-only); `SQLException` propagates to the existing `catch` block, which logs at `Level.WARNING`; the `finally` block closes `ResultSet`, `Statement`, and `Connection` in that order.

## Fix

Complete fixed `Case01B.java`:

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

`Case01A.java` needs no change: the parameter read there is a legitimate input point, and the weakness is entirely in how the value is combined with SQL at the sink.

No library change is required. The fix uses `java.sql.PreparedStatement` from the JDK, already in scope through the existing `import java.sql.*;`.

## Explanation

The query text is now a fixed string literal containing a `?` placeholder, and the untrusted value is supplied separately through `setString(1, data)` rather than being concatenated into the SQL. The statement is parsed and its execution plan fixed before the parameter value is ever attached, so the driver transmits `data` as a typed value bound to that placeholder; it is never parsed as SQL text. Quote characters, comment sequences, `UNION`, `OR '1'='1`, and stacked-statement separators inside the input therefore have no syntactic effect - they can only ever be part of the string being compared against the `name` column, which is what the original code intended. The declaration changed from `Statement` to `PreparedStatement` because `prepareStatement` returns the more specific type needed to call `setString`, and `executeQuery()` is now the no-argument form, since passing a SQL string to that overload on a `PreparedStatement` would defeat the binding. Note that switching to `PreparedStatement` is only protective in combination with the placeholder: had the concatenated string been handed to `prepareStatement` instead, the injection would already have occurred before the statement was prepared.

## Behaviour changes

- **Statement variable type (`Statement` -> `PreparedStatement`)** - required, because parameter binding via `setString` is not available on `Statement`. `PreparedStatement` extends `Statement`, so the `finally` block's null check and `close()` call are unaffected.
- **`createStatement()` -> `prepareStatement(sql)`** - required to attach the parameterized SQL to the statement. Both are the no-option overloads, so the returned `ResultSet` keeps the same driver-default type, concurrency, and holdability (forward-only, read-only) that the original relied on. No result-set option was supplied where the original left a default.
- **SQL parse timing** - the query is now parsed at the `prepareStatement` call rather than at `executeQuery`. Any `SQLException` from a malformed statement therefore surfaces one line earlier, but still inside the same `try` block and is handled by the same `catch (SQLException)` at the same log level, so the observable failure behaviour is unchanged.
- Otherwise **none**. The returned `ResultSet` is assigned to the same variable, only `getRow()` is consumed and written through the same `IO.writeLine` call, no previously discarded output is surfaced, no query semantics changed (the `name` comparison matches exactly the same rows for any given input), and the resource-closing order in `finally` is untouched.

Confidence: high. The full source-to-sink path is visible in the two supplied files, and the fix is a direct parameterization of a single-value string comparison with no dynamic identifiers or structure requiring allowlist handling.

Assumptions: none material. `IO.getDBConnection()` is taken to return a standard JDBC `Connection` - consistent with the `java.sql` types used throughout - so `prepareStatement` is available on it.
