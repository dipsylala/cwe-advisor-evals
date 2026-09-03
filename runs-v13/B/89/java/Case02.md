## Verdict

Confirmed SQL Injection (CWE-89). Line 28 in Case02D.java concatenates untrusted user input directly into a SQL query string passed to `Statement.executeQuery()`. An attacker can inject SQL syntax via the `name` parameter to manipulate query logic, bypass authentication, or access unauthorized data.

## Source

User input originates in Case02A.java at line 15:
```java
data = request.getParameter("name");
```

This untrusted value flows through Case02B → Case02C → Case02D, reaching the SQL sink at Case02D.java line 28.

## Fix

Replace the `Statement` with a `PreparedStatement` and use parameterized queries with placeholders. Change line 24-28 in Case02D.java from:

```java
sqlStatement = dbConnection.createStatement();

// SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

To:

```java
PreparedStatement sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
sqlStatement.setString(1, data);

// No longer vulnerable: parameter is bound, not concatenated
resultSet = sqlStatement.executeQuery();
```

Also update the type declaration on line 18 from `Statement sqlStatement` to `PreparedStatement sqlStatement`.

## Explanation

Parameterized queries ensure user input is treated strictly as data, never as executable SQL syntax. The `?` placeholder marks the position where a bound value will be substituted, and `setString(1, data)` provides the actual value through the driver's type-safe binding mechanism. Even if `data` contains single quotes, SQL metacharacters, or injection syntax like `' OR '1'='1`, the database driver treats the entire value as a literal string and will not parse it as SQL structure. This is the only effective defence against SQL injection in JDBC; manual escaping or keyword-based filtering is unreliable and defeated by context-dependent encoding, unquoted numeric contexts, and inline comments.

## Behaviour changes

- The query now safely accepts any input from the `name` parameter without risk of injection.
- Special characters and SQL metacharacters in the input are treated as literal string data, not query syntax.
- Performance impact is neutral or positive: prepared statements are often cached by the driver, enabling query plan reuse.
- The result set behavior is unchanged; only the parameterization mechanism is modified.
- If input validation is desired as a secondary layer, it can be added before `setString()`, but parameterization is the primary and sufficient defence.
