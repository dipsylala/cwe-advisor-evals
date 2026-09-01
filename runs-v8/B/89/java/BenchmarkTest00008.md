## Verdict
exploitable

## Source
User input from HTTP header `request.getHeader("BenchmarkTest00008")` (line 46), URL-decoded but not sanitized for SQL (line 50).

## Fix
**Vulnerable code:**
```java
String param = "";
if (request.getHeader("BenchmarkTest00008") != null) {
    param = request.getHeader("BenchmarkTest00008");
}

param = java.net.URLDecoder.decode(param, "UTF-8");

String sql = "{call " + param + "}";  // SQL INJECTION: untrusted param directly concatenated

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    java.sql.ResultSet rs = statement.executeQuery();
```

**Fixed code:**
```java
String param = "";
if (request.getHeader("BenchmarkTest00008") != null) {
    param = request.getHeader("BenchmarkTest00008");
}

param = java.net.URLDecoder.decode(param, "UTF-8");

String sql = "{call proc(?)}";  // Parameterized query with placeholder

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    statement.setString(1, param);  // Bind untrusted input as parameter, not code
    java.sql.ResultSet rs = statement.executeQuery();
```

## Explanation
The original code concatenates untrusted user input directly into the SQL string before passing it to `prepareCall()`, making SQL injection possible. The fix replaces string concatenation with a parameterized CallableStatement using `?` placeholders. The untrusted `param` value is bound separately using `setString(1, param)`, ensuring it is always treated as data, not as SQL code structure. This eliminates the injection vector while preserving the functional behavior of passing the parameter to the stored procedure.

## Behaviour changes
- SQL string changed from `"{call " + param + "}"` to `"{call proc(?)}"`
- Added call to `statement.setString(1, param)` to bind the parameter
- The parameter value is now passed through the JDBC binding mechanism instead of string concatenation, which prevents SQL injection syntax from being interpreted as executable SQL
- No impact on return value, exception handling, or result set processing
