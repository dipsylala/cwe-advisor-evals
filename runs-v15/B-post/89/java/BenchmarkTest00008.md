## Verdict

Exploitable. Untrusted input from `request.getHeader()` is directly concatenated into a SQL string (line 52) before a `CallableStatement` is created and executed. String concatenation of user-controlled data into SQL always precedes the prepared statement, rendering the prepared statement's protection ineffective.

## Source

`request.getHeader("BenchmarkTest00008")` (line 45-46), URL-decoded on line 50 to produce `param`.

## Fix

**Vulnerable code (lines 52-59):**
```java
String sql = "{call " + param + "}";

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    // SAST FINDING: CWE-89 (SQL Injection) - a SQL statement is built from request data and executed. Sink is the next statement.
    java.sql.ResultSet rs = statement.executeQuery();
    org.owasp.benchmark.helpers.DatabaseHelper.printResults(rs, sql, response);
```

**Fixed code:**
```java
String sql = "{call someStoredProc(?)}";

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    statement.setString(1, param);
    java.sql.ResultSet rs = statement.executeQuery();
    org.owasp.benchmark.helpers.DatabaseHelper.printResults(rs, sql, response);
```

## Explanation

The original code builds the SQL string by concatenating untrusted input directly into the query before passing it to `prepareCall()`. This allows an attacker to inject arbitrary SQL or stored procedure names through the HTTP header. The fix uses a parameterized `CallableStatement` with a placeholder (`?`) for the parameter position, and binds the untrusted input using `setString()`. This ensures the input is treated as data (a parameter value) rather than executable SQL structure. The stored procedure name (`someStoredProc`) is now fixed and controlled by the application, while the parameter value is safely separated from the SQL structure.

## Behaviour changes

The fix changes the SQL from dynamic procedure selection to a fixed stored procedure `someStoredProc` with a parameterized input. If the application genuinely requires dynamic procedure names, that portion must be validated against a server-side allowlist of permitted procedure names before building the SQL string, and the allowlist value (not the original input) should be used in the string. The `setString()` call adds an explicit parameter binding that was previously absent, and the `sql` variable passed to `printResults()` now contains the parameterized template with `?` rather than the interpolated value.
