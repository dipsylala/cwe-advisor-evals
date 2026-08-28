## Verdict

exploitable

## Source

Untrusted data enters at `Case03A.handle()` (Case03A.java:15) via `request.getParameter("name")`, a caller-controlled HTTP request parameter on a servlet entry point.

Path to the sink, unmodified at every hop - no validation, encoding, canonicalisation, or reassignment occurs anywhere along the chain:

1. `Case03A.java:15` - `data = request.getParameter("name")`
2. `Case03A.java:17` - `(new Case03B()).handleSink(data, request, response)`
3. `Case03B.java:12` - passes `data` straight through to `Case03C.handleSink`
4. `Case03C.java:12` - passes `data` straight through to `Case03D.handleSink`
5. `Case03D.java:12` - passes `data` straight through to `Case03E.handleSink`
6. `Case03E.java:28` - sink: `sqlStatement.executeQuery("select * from users where name='" + data + "'")`

The value is concatenated into a single-quoted string literal in the SQL text and executed by `java.sql.Statement.executeQuery()`. A request such as `?name=' OR '1'='1` closes the literal and appends attacker-chosen SQL, so query logic is fully controllable. The path is reachable and unbroken.

Sink contract as it currently stands, which the fix has to preserve:

- Returns a `ResultSet` assigned to `resultSet`; the only consumer is `IO.writeLine(resultSet.getRow())` on the next line, which reports the cursor position (0, since `next()` is never called). No row data is read.
- Discards the entire result set contents.
- Leaves arguments implicit: `createStatement()` is called with no arguments, so the statement uses the JDBC defaults `TYPE_FORWARD_ONLY` and `CONCUR_READ_ONLY`.
- On failure throws `SQLException`, caught and logged at `WARNING` without rethrow; the `finally` block closes `resultSet`, `sqlStatement`, and `dbConnection` independently.

## Fix

Complete fixed `Case03E.java`:

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

No changes are required in `Case03A.java`, `Case03B.java`, `Case03C.java`, or `Case03D.java`; those are pass-through hops and the fix belongs at the sink where the SQL text is assembled.

## Explanation

The query text is now a fixed string literal containing a `?` placeholder in place of the interpolated, quote-delimited value, and the untrusted parameter is supplied separately through `PreparedStatement.setString(1, data)`. The driver sends the statement structure and the bound value over separate channels, so `data` is only ever interpreted as a string value in the `name` comparison and can never contribute SQL syntax - the embedded quote that made `' OR '1'='1` work is now part of the value being compared rather than a delimiter that terminates it. This is a structural fix rather than a filtering one: no escaping, blocklisting, or length check is involved, so it holds for every possible input without maintenance. The statement variable's declared type changes from `Statement` to `PreparedStatement` because `setString` is declared on the narrower interface; `PreparedStatement` extends `Statement`, so the existing `close()` call in the `finally` block is unaffected. Parameter binding covers value positions only - had the untrusted data been used as a table or column name or an `ORDER BY` direction, a placeholder would not have been usable there and allowlist validation against a fixed set of identifiers would have been needed instead. That is not the case here, where `data` is purely a comparison value.

## Behaviour changes

None to the sink contract. Each difference from the original, with its reason:

- **`sqlStatement` declared as `PreparedStatement` rather than `Statement`** - required so `setString` is available; `PreparedStatement` is a subinterface of `Statement`, and the only other use of the variable is `close()` in the `finally` block, which resolves identically. No other code in the file or the call chain observes this type.
- **`createStatement()` replaced by `prepareStatement(sql)`** - required to bind the parameter. The original supplied no result-set type or concurrency arguments, and the single-argument `prepareStatement` overload applies the same JDBC defaults (`TYPE_FORWARD_ONLY`, `CONCUR_READ_ONLY`), so the implicit arguments are preserved rather than silently widened.
- **`executeQuery()` called with no argument instead of a SQL string** - the SQL now lives on the prepared statement. It still returns a `ResultSet`, still assigned to `resultSet`, still consumed only by `IO.writeLine(resultSet.getRow())`, and no discarded output is newly surfaced.
- **Failure behaviour unchanged** - `prepareStatement`, `setString`, and `executeQuery` all throw `SQLException`, which the existing `catch` handles with the same `WARNING` log and no rethrow. The `finally` cleanup of all three resources is untouched.
- **Return value and console output unchanged** - `getRow()` is called before any `next()`, so it reports `0` both before and after the change.
- **One input-handling nuance, noted for completeness:** if the `name` parameter is absent from the request, `request.getParameter` returns `null`. The original produced `name='null'`, matching rows whose name is the literal text `null`; the fixed version binds SQL `NULL`, and `name = NULL` matches nothing. This is a consequence of parameterisation, not an added behaviour, and it is unobservable here because the only output is the pre-iteration cursor position, which is `0` in both cases. Flagged rather than worked around, since reintroducing the old semantics would mean rebuilding the string.

Confidence: high. The full source-to-sink chain was read directly across all five files, with no reflection, dynamic dispatch, framework indirection, or configuration-driven routing anywhere in it. No assumptions were required to resolve the finding.
