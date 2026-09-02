## Verdict

Exploitable. CWE-89 (SQL Injection), confidence: high.

## Source

`Case01A.handle()` reads the untrusted parameter `data = request.getParameter("name")` (an
attacker-controlled HTTP request parameter) and passes it unmodified into
`(new Case01B()).handleSink(data, request, response)`.

## Fix

Vulnerable code (`Case01B.java`, line ~14-30):

```java
public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
{

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
    ...
}
```

Fixed code:

```java
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
    ...
}
```

(The `catch`/`finally` blocks are unchanged and still apply - `sqlStatement.close()` in `finally`
works unmodified since `PreparedStatement` extends `Statement`.)

## Explanation

The sink built a `select` query by concatenating the raw `name` request parameter directly into
the SQL text, so any quote or SQL metacharacter in `data` alters the query's structure (e.g.
`' OR '1'='1`). The fix replaces `Statement.createStatement()` + string-concatenated
`executeQuery(String)` with `Connection.prepareStatement()` using a `?` placeholder for the value
position, and binds `data` with `setString(1, data)` before calling the no-argument
`executeQuery()`. The database driver now treats `data` strictly as a literal value, never as SQL
syntax, which closes the injection regardless of its content.

## Behaviour changes

- `sqlStatement` declared type changed from `Statement` to `PreparedStatement` - required so the
  code can call `prepareStatement()`/`setString()`; `PreparedStatement` is a subtype of
  `Statement`, so the existing `finally` block's `sqlStatement.close()` call and null-check behave
  identically.
- `executeQuery(String)` (query text supplied at call time) became `executeQuery()` (no
  arguments, using the pre-bound statement) - the query text and the now-parameterized value are
  set up beforehand via `prepareStatement()`/`setString()` instead of being passed together as one
  string; the query executed against the database is equivalent for legitimate (non-malicious)
  input.
- No other change: the return value used (`resultSet`), what is logged, what is discarded, and
  all error/close handling in `catch`/`finally` are unchanged.
