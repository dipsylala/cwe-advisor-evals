## Verdict

Exploitable. CWE-89 (SQL Injection), confidence: high.

## Source

`Case03A.handle()`, line 15: `data = request.getParameter("name");` - an HTTP request parameter, fully attacker-controlled, with no validation or encoding applied anywhere along the call chain.

## Fix

Vulnerable code (`Case03E.java`, lines 17-28):

```java
Connection dbConnection = null;
Statement sqlStatement = null;
ResultSet resultSet = null;

try
{
    dbConnection = IO.getDBConnection();
    sqlStatement = dbConnection.createStatement();

    // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
    resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

Fixed code:

```java
Connection dbConnection = null;
PreparedStatement sqlStatement = null;
ResultSet resultSet = null;

try
{
    dbConnection = IO.getDBConnection();
    sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
    sqlStatement.setString(1, data);

    resultSet = sqlStatement.executeQuery();
```

(The `finally` block's `sqlStatement.close()` call is unchanged - `PreparedStatement.close()` has the same signature it inherits from `Statement`.)

## Explanation

`data` originates from `request.getParameter("name")` in `Case03A` and is passed unmodified through `Case03B` -> `Case03C` -> `Case03D` into `Case03E.handleSink()`, where it is concatenated directly into a SQL string executed via `Statement.executeQuery(String)`. Because the value is spliced into the query text before the driver ever sees it, an attacker can supply input such as `' OR '1'='1` to alter the query's logic (or worse, chain additional statements/clauses). The fix replaces `Statement` with `PreparedStatement`: the query is now compiled from a static string containing a `?` placeholder, and `data` is bound afterward via `setString(1, data)`, so the JDBC driver always treats it as a literal value rather than as SQL syntax, regardless of its content.

## Behaviour changes

- `sqlStatement`'s declared type changes from `Statement` to `PreparedStatement` - required to call `prepareStatement()`/`setString()`; `PreparedStatement` still satisfies every later use of the variable (`executeQuery()` with no arguments, `close()` in the `finally` block), so no other line needs to change.
- No change to what is returned, discarded, or thrown: `executeQuery()` still returns the same `ResultSet` shape for a matching `name`, `IO.writeLine(resultSet.getRow())` is untouched, and the existing `SQLException` catch/finally handling around connection/statement/result-set cleanup applies identically to `PreparedStatement` as it did to `Statement`.
- All other files in the call chain (`Case03A`-`Case03D`) are unchanged; `data` continues to flow through them unmodified, since the fix is applied at the sink where the SQL is constructed and executed.
