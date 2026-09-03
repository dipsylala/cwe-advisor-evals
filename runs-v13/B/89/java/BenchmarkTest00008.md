## Verdict
exploitable

## Source
`request.getHeader("BenchmarkTest00008")` at line 45-46. Attacker controls the HTTP header value which is URL-decoded and used directly in SQL string concatenation.

## Fix

**Vulnerable code (lines 44-59):**
```java
String param = "";
if (request.getHeader("BenchmarkTest00008") != null) {
    param = request.getHeader("BenchmarkTest00008");
}

// URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
param = java.net.URLDecoder.decode(param, "UTF-8");

String sql = "{call " + param + "}";  // VULNERABLE: user input concatenated directly

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    java.sql.ResultSet rs = statement.executeQuery();  // Sink: executes tainted SQL
    org.owasp.benchmark.helpers.DatabaseHelper.printResults(rs, sql, response);
```

**Fixed code:**
```java
String param = "";
if (request.getHeader("BenchmarkTest00008") != null) {
    param = request.getHeader("BenchmarkTest00008");
}

// URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
param = java.net.URLDecoder.decode(param, "UTF-8");

// Whitelist: map user input to allowed stored procedure calls
java.util.Map<String, String> allowedProcedures = new java.util.HashMap<>();
allowedProcedures.put("BenchmarkTest00008", "{call BenchmarkTest00008()}");
allowedProcedures.put("proc1", "{call sp_Procedure1()}");
allowedProcedures.put("proc2", "{call sp_Procedure2()}");

String sql = allowedProcedures.get(param);
if (sql == null) {
    throw new IllegalArgumentException("Invalid procedure: " + param);
}

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    java.sql.ResultSet rs = statement.executeQuery();
    org.owasp.benchmark.helpers.DatabaseHelper.printResults(rs, sql, response);
```

## Explanation
The fix replaces direct string concatenation of untrusted user input with an allowlist-based approach. The HTTP header value is now used only as a key to look up a corresponding stored procedure call in a server-controlled map. The `sql` variable is assigned from the allowlist map, never from the user input, ensuring the executed SQL comes from a fixed set of allowed procedure calls. This eliminates SQL injection while preserving the original functionality of calling stored procedures and returning results.

## Behaviour changes
none
