# Case14 - CWE-89 (SQL Injection)

- **Location:** `evals/cases-v2/Case14/Case14B.java:29` (`sqlStatement.executeQuery()`)
- **Confidence:** high

## Verdict

not_exploitable

## Source

Untrusted data enters at `Case14A.java:15`, where `handle(HttpServletRequest, HttpServletResponse)` reads the attacker-controlled HTTP query/form parameter `name` via `request.getParameter("name")` into the local `data`.

Path to the sink:

1. `Case14A.java:15` - `data = request.getParameter("name");` (taint source).
2. `Case14A.java:17` - `data` is passed unmodified as the first argument to `(new Case14B()).handleSink(data, request, response)`.
3. `Case14B.java:25` - the SQL text is built from a single string literal with a bind placeholder: `dbConnection.prepareStatement("select * from users where name=?")`. The tainted value takes no part in constructing this string - there is no concatenation, `String.format()`, or template substitution anywhere on the path.
4. `Case14B.java:26` - `sqlStatement.setString(1, data);` binds the tainted value to placeholder `1`.
5. `Case14B.java:29` - `resultSet = sqlStatement.executeQuery();` executes the already-parsed statement (reported sink).

The breaking link is between steps 3 and 4. The query's structure is fixed by a compile-time constant before any untrusted data is introduced, and `data` reaches the database only as a bound parameter value. The driver transports it out-of-band from the SQL text, so quotes, comments, semicolons, or operators inside `name` are matched literally against the `name` column and can never be parsed as query syntax. Nothing downstream re-reads the value and re-concatenates it into another query, so there is no second-order path either.

## Fix

No change is proposed. The code at the reported location already implements the correct defence (a static SQL string with a `?` placeholder plus `setString()` binding), and modifying it would only risk regressions.

For completeness, the reported sink and its surrounding statements are reproduced unchanged:

```java
dbConnection = IO.getDBConnection();
sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
sqlStatement.setString(1, data);

resultSet = sqlStatement.executeQuery();

IO.writeLine(resultSet.getRow());
```

Recommended disposition: mark the finding as a false positive with a documented justification referencing the literal SQL string at `Case14B.java:25` and the `setString()` binding at line 26. If the finding is re-triaged later, the check to re-run is whether that SQL string is still a single literal - the moment any part of it is concatenated, the conclusion no longer holds.

## Explanation

Nothing changed, because the reported path is already parameterized end to end. `PreparedStatement` is not safe by virtue of its type - it protects only when the SQL string itself was never built from untrusted input - so the trace was judged on what the query string was assembled from rather than on which class executes it. Here the string is a lone literal containing a `?` placeholder, and the request parameter is supplied separately through `setString(1, data)`, meaning the statement's parse tree is fully determined before the attacker's value exists in the query at all. The scanner most likely flagged `executeQuery()` as a known sink reachable from `request.getParameter()` across a method boundary without modelling the intervening bind, which is the classic shape of a cross-file false positive on this rule. Rewriting working parameterized code would add risk without removing any weakness, so the correct outcome is to leave the code alone and suppress the finding with the justification recorded above.

## Behaviour changes

none - no code change is proposed, so the sink contract at `Case14B.java:29` is untouched: `executeQuery()` still returns the `ResultSet` assigned to `resultSet` and consumed by `IO.writeLine(resultSet.getRow())`, the same `SQLException` handling and `finally`-block close ordering apply, and no previously discarded output is surfaced.

## Assumptions

- The supporting class `testcasesupport.IO` (`IO.getDBConnection()`, `IO.writeLine()`, `IO.logger`) is outside the reviewed call chain and was not inspected. This does not affect the verdict: the SQL text at `Case14B.java:25` is a self-contained literal, so no behaviour of `IO` could reintroduce structural injection at the reported sink. `getDBConnection()` is assumed to return a standard JDBC `Connection` whose `prepareStatement`/`setString` honour the JDBC binding contract.
- `Case14A.handle()` is assumed to be the servlet entry point invoked by the container for this case; the verdict does not depend on this, since any caller supplying a `String` reaches the same bound-parameter path.
