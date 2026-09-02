## Verdict
exploitable

## Source
`request.getHeader("BenchmarkTest00008")` at line 45-46, URL-decoded at line 50, concatenated into SQL at line 52.

## Fix

**Vulnerable Code:**
```java
String param = "";
if (request.getHeader("BenchmarkTest00008") != null) {
    param = request.getHeader("BenchmarkTest00008");
}

// URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
param = java.net.URLDecoder.decode(param, "UTF-8");

String sql = "{call " + param + "}";  // VULNERABLE: SQL injection via string concatenation

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    java.sql.ResultSet rs = statement.executeQuery();
    org.owasp.benchmark.helpers.DatabaseHelper.printResults(rs, sql, response);
```

**Fixed Code:**
```java
String param = "";
if (request.getHeader("BenchmarkTest00008") != null) {
    param = request.getHeader("BenchmarkTest00008");
}

// URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
param = java.net.URLDecoder.decode(param, "UTF-8");

// Allowlist of permitted stored procedure names
final Set<String> ALLOWED_PROCEDURES = new java.util.HashSet<>(
    java.util.Arrays.asList("sp_procA", "sp_procB", "sp_procC")
);

// Validate against allowlist before constructing SQL
if (!ALLOWED_PROCEDURES.contains(param)) {
    response.getWriter().println("Error: Invalid procedure name.");
    return;
}

String sql = "{call " + param + "}";  // Now safe: param is from allowlist

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    java.sql.ResultSet rs = statement.executeQuery();
    org.owasp.benchmark.helpers.DatabaseHelper.printResults(rs, sql, response);
```

## Explanation
Stored procedure names cannot be parameterized with placeholders and must be validated against a server-controlled allowlist before SQL construction. The fix defines a whitelist of permitted procedure names and checks that the user-supplied input matches one of them exactly before concatenating into the SQL string. This ensures the procedure name can only be one of the explicitly approved values, preventing SQL injection attacks that attempt to manipulate or add malicious procedure calls. An input validation layer as secondary defence (the allowlist check) combined with a fixed set of known-safe procedure names substituted into the SQL closes the injection path.

## Behaviour changes
- Added allowlist validation with early return on invalid procedure name: if the header value does not match one of the approved procedure names, the handler outputs an error message and exits without executing a database query.
- Restricted procedure execution to only the procedures in the `ALLOWED_PROCEDURES` set; the original code permitted arbitrary procedure execution.
- Added a new import requirement for `java.util.Set`, `java.util.HashSet`, and `java.util.Arrays` if not already present.
