## Verdict

Exploitable

## Source

HTTP request header via `request.getHeaders("BenchmarkTest00018")` at line 45, extracted at line 48, URL-decoded at line 52. The `param` variable carries untrusted user input into the SQL string concatenation.

## Fix

**Vulnerable code (lines 54–60):**
```java
String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";

try {
    java.sql.Statement statement =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
    // SAST FINDING: CWE-89 (SQL Injection) - a SQL statement is built from request data and executed. Sink is the next statement.
    int count = statement.executeUpdate(sql);
```

**Fixed code:**
```java
String sql = "INSERT INTO users (username, password) VALUES ('foo', ?)";

try {
    java.sql.Connection conn =
            org.owasp.benchmark.helpers.DatabaseHelper.getConnection();
    java.sql.PreparedStatement statement = conn.prepareStatement(sql);
    statement.setString(1, param);
    int count = statement.executeUpdate();
```

## Explanation

The original code concatenates untrusted user input (`param`) directly into the SQL string, which is then executed. An attacker can inject SQL syntax to manipulate the query logic—for example, closing the string early with `' OR '1'='1`) and appending arbitrary SQL commands.

The fix replaces string concatenation with a parameterized query using `PreparedStatement` and the `?` placeholder. The `setString(1, param)` call binds the user input as data, not as SQL structure, so the database driver interprets it as a literal string value rather than executable code. This is the primary defence against SQL injection in Java and eliminates the vulnerability entirely.

## Behaviour changes

**SQL execution method changed:** Original used `Statement.executeUpdate(String sql)` with the SQL string as the argument; fixed version uses `PreparedStatement.executeUpdate()` with no argument (SQL is already prepared). The return value (`int` count of affected rows) remains identical.

**Connection handling:** Original obtained a `Statement` directly via `DatabaseHelper.getSqlStatement()`; fixed version obtains a `Connection` via `DatabaseHelper.getConnection()` and creates a `PreparedStatement` from it. This requires the helper to provide `getConnection()`, which is a standard JDBC pattern.

**No other functional changes:** URL decoding, result handling, and error handling remain identical.
