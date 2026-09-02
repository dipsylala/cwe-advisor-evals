## Verdict

not_exploitable (CWE-89, SQL Injection)

- Location: `Case14B.java`, line 29 (`sqlStatement.executeQuery()`)
- Confidence: high

## Source

`request.getParameter("name")` in `Case14A.handle()` (line 15). The value is passed as the `data` parameter into `Case14B.handleSink(data, request, response)` (line 17), with no transformation in between.

## Fix

No fix required. The reported sink is already using the safe pattern.

Data flow to the sink:

1. `Case14A.handle()` reads attacker-controlled input into `data` and forwards it unchanged to `Case14B.handleSink()`.
2. `Case14B.handleSink()` builds the query from a fixed string literal only: `dbConnection.prepareStatement("select * from users where name=?")` (line 25) — no concatenation, `String.format()`, or other text-building with `data` anywhere in the query text.
3. `data` reaches the database exclusively through `sqlStatement.setString(1, data)` (line 26), which binds it as a parameter value, not as SQL text.
4. `sqlStatement.executeQuery()` (line 29) then executes the already-parameterized statement.

This is exactly the safe pattern the knowledge base prescribes for Java: `PreparedStatement` with a `?` placeholder plus `setString()`, where the SQL text is static and the tainted value only ever reaches the query as a bound parameter. The link the SAST tool's path implies — untrusted input reaching `executeQuery()` as part of the query structure — does not exist here; `data` cannot influence the query's structure regardless of its content, so no malicious value of `name` can alter the SQL logic.

## Explanation

The finding flags the `executeQuery()` call because it is the point where a query built from tainted input would run, but in this call chain the query string passed to `prepareStatement()` is a compile-time constant and the tainted value is bound afterward via `setString()`. JDBC's parameter binding treats the value strictly as data for the `name` column comparison; it is never parsed as SQL syntax, so standard injection payloads (e.g. `' OR '1'='1`) would be matched literally against the `name` column rather than altering the query. No code change is needed at this sink.

## Behaviour changes

none — no code was modified.
