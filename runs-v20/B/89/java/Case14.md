## Verdict

not_exploitable (CWE-89, SQL Injection) - confidence: high

The reported sink at `Case14B.java:29` (`sqlStatement.executeQuery()`) is not reachable as an injection because the query text and the parameter binding are already correct: the SQL is a static string with a `?` placeholder, and the tainted value is bound with `PreparedStatement.setString()`, never concatenated into the query text. Per the loaded CWE-89 Java guidance, a `PreparedStatement` is judged safe or not "by what the SQL string was built from, not by which class executes it" - here the string is `"select * from users where name=?"`, built from no user input at all, and `data` reaches the driver only as a bound parameter. That is exactly the parameterized-query pattern the guidance prescribes as the fix, already in place.

## Source

- **Source**: `Case14A.handle()`, line 15 - `data = request.getParameter("name")` (attacker-controlled HTTP request parameter).
- **Propagation**: `Case14A.handle()`, line 17 - `data` passed unmodified into `Case14B.handleSink(data, request, response)`.
- **Sink location reported**: `Case14B.handleSink()`, line 29 - `resultSet = sqlStatement.executeQuery();`
- **Breaking link**: `Case14B.handleSink()`, lines 25-26:
  - Line 25: `sqlStatement = dbConnection.prepareStatement("select * from users where name=?");` - the SQL text is a fixed literal containing only a `?` placeholder; `data` never touches this string.
  - Line 26: `sqlStatement.setString(1, data);` - `data` is bound as a typed parameter through the JDBC driver's parameter-binding mechanism, not interpolated into SQL text.
  - By the time execution reaches line 29, `data` can only ever be interpreted as the value of the `name` column comparison - it cannot alter the query's structure, so no injection payload placed in the `name` request parameter can change the SQL that runs.

## Fix

No fix required. No file was changed.

## Explanation

The finding flags the query-execution call, but the vulnerability class it names requires untrusted data to reach the SQL text itself (via concatenation, `String.format()`, or similar), and that path does not exist here: the statement is prepared from a static string with a placeholder, and the only use of `data` is as a bound parameter via `setString()`. This is precisely the parameterized-query defence that CWE-89 remediation prescribes, already applied at the point where `data` enters the query. Since the sink's only tainted input arrives through the safe binding API rather than through the query text, there is no code-level change that would reduce risk here; introducing one (e.g., re-validating or re-escaping `data` before `setString()`) would be redundant defence-in-depth rather than a fix for an actual weakness, and was not applied in order to avoid unjustified scope creep on a finding that traces to a non-exploitable path.

## Behaviour changes

none - no code was modified.
