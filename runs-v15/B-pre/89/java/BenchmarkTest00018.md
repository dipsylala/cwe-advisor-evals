## Verdict

exploitable

## Source

User-controlled data flows from the request headers via `request.getHeaders("BenchmarkTest00018")` through the `param` variable at lines 45-48. The data is URL-decoded at line 52 but remains untrusted.

## Fix

**Vulnerable code (line 54-60):**
```java
String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";

try {
    java.sql.Statement statement =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
    int count = statement.executeUpdate(sql);
```

**Fixed code:**
```java
String sql = "INSERT INTO users (username, password) VALUES ('foo', ?)";

try {
    java.sql.PreparedStatement statement =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection().prepareStatement(sql);
    statement.setString(1, param);
    int count = statement.executeUpdate();
```

## Explanation

The vulnerability is closed by replacing string concatenation with a parameterized query using `PreparedStatement`. The `?` placeholder marks where the parameter will be bound, and `setString(1, param)` passes the user input as typed data rather than as SQL structure. This ensures the database driver treats the entire `param` value as a string literal, preventing any SQL metacharacters in the input from being interpreted as query syntax. The `PreparedStatement` also improves performance through statement caching and provides defense-in-depth against SQL injection.

## Behaviour changes

The following changes are necessary to close the vulnerability:

1. **Statement type change**: `Statement` becomes `PreparedStatement` - required because only prepared statements support parameter binding. This is the safe pattern for executing parameterized queries in Java.
2. **SQL string modification**: The query string changes from concatenation to a static template with `?` placeholders - this transfers the injection sink from the SQL string to the parameter binding layer where the database driver enforces type safety.
3. **Parameter binding**: A new call `statement.setString(1, param)` is added to bind the user input - this is mandatory to populate the placeholder and is where the untrusted data enters the query safely.
4. **Return value handling**: `executeUpdate()` is called without arguments instead of with the pre-built SQL string - this is the standard `PreparedStatement` API and preserves the existing return value contract (returns row count).

The fix does not alter the query's semantics, the returned data, or the exception behavior. The application continues to insert the same data into the same table; the only change is that SQL metacharacters in `param` are now safely neutralized.
