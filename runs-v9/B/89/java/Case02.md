## Verdict

- **CWE-89** (SQL Injection) - **exploitable**
- Location: `Case02D.java`, line 28 (sink), `sqlStatement.executeQuery(...)`
- Confidence: high

## Source

`request.getParameter("name")` in `Case02A.handle()` (line 15). The value is assigned to `data` and passed unmodified through the call chain:

- `Case02A.handle()` -> `Case02B.handleSink(data, ...)` (line 17)
- `Case02B.handleSink()` -> `Case02C.handleSink(data, ...)` (line 12)
- `Case02C.handleSink()` -> `Case02D.handleSink(data, ...)` (line 12)

No validation, encoding, or type coercion is applied to `data` at any point in the chain. It reaches `Case02D.handleSink()` as the same attacker-controlled `String` taken directly from the HTTP request parameter.

## Fix

Vulnerable code (`Case02D.java`, lines 17-30):

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

    IO.writeLine(resultSet.getRow());
}
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

    IO.writeLine(resultSet.getRow());
}
```

(`java.sql.*` is already imported, so `PreparedStatement` requires no new import. The `finally` block that closes `sqlStatement` is unchanged - `PreparedStatement` extends `Statement`, so `sqlStatement.close()` still applies.)

## Explanation

The original code built the SQL statement by concatenating the untrusted `data` value directly into the query text, so any single quote or SQL metacharacter in the `name` request parameter would change the query's structure (e.g. `' OR '1'='1` turns the `WHERE` clause into a tautology, or a `UNION SELECT` could exfiltrate other tables). The fix replaces the `Statement`/`createStatement()` pair with `PreparedStatement`/`prepareStatement()` using a `?` placeholder for the value position, and binds `data` with `setString(1, data)`. The database driver then always treats the bound value as literal data, never as SQL syntax, which closes the injection regardless of what characters `data` contains.

## Behaviour changes

- `sqlStatement`'s declared type changes from `Statement` to `PreparedStatement`. Required to use parameter binding; it is still a `Statement` for `close()` purposes in the `finally` block, so cleanup behaviour is unchanged.
- The query text changes from an inline literal to a `?` placeholder, with the value supplied via `setString(1, data)` instead of string concatenation. The resulting query is semantically equivalent for any value that does not contain SQL metacharacters (`select * from users where name='<value>'`); for values that do, the fixed version now treats them as literal data instead of query structure, which is the intended correction.
- `executeQuery()` is called with no arguments instead of the built string, since the query and its parameter are now supplied separately. Return value (`ResultSet`), what the caller does with it (`resultSet.getRow()` passed to `IO.writeLine()`), and error handling (`SQLException` caught and logged) are all unchanged.
- No other behaviour changes. Everything the sink returns, discards, defaults, or throws on failure is preserved.
