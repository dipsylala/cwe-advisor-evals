## Verdict

Exploitable. User-controlled HTTP header input is directly concatenated into a SQL callable statement string at line 52 and executed at line 59, enabling SQL injection. The use of `prepareCall()` does not mitigate this vulnerability because the SQL string is already constructed unsafely before being passed to the method.

## Source

Line 46: `request.getHeader("BenchmarkTest00008")` — attacker-controlled HTTP header. The header value is URL-decoded at line 50 but remains untrusted user input. Trace: request header → param variable (lines 45-50) → string concatenation into sql (line 52) → callable statement execution (lines 57-59).

## Fix

**Vulnerable code (lines 44-59):**
```java
String param = "";
if (request.getHeader("BenchmarkTest00008") != null) {
    param = request.getHeader("BenchmarkTest00008");
}

param = java.net.URLDecoder.decode(param, "UTF-8");

String sql = "{call " + param + "}";

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

// Validate procedure name against allowlist of permitted procedures
java.util.Map<String, String> allowedProcedures = new java.util.HashMap<>();
allowedProcedures.put("procedure1", "procedure1");
allowedProcedures.put("procedure2", "procedure2");

String allowedProc = allowedProcedures.get(param);
if (allowedProc == null) {
    throw new IllegalArgumentException("Invalid or unauthorized procedure: " + param);
}

String sql = "{call " + allowedProc + "}";

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    java.sql.ResultSet rs = statement.executeQuery();
```

## Explanation

The original code directly concatenates user-supplied input into the SQL string before passing it to `prepareCall()`. `PreparedStatement` and `CallableStatement` are only safe when parameterized with `?` placeholders and bound parameters; calling `prepareCall()` with a pre-constructed string that already contains untrusted data provides no injection protection. The fix implements allowlist validation using a server-side map of permitted procedure names. User input is validated against this map, and only canonical procedure names from the map are used to construct the SQL statement. This ensures untrusted input cannot manipulate the procedure call structure. The developer must populate `allowedProcedures` with the actual procedure names their application is allowed to call.

## Behaviour changes

- Added `HashMap` initialization for `allowedProcedures` with example procedure name mappings. Developer must update with actual permitted procedures specific to their application.
- Added map lookup and null check. The query now uses `allowedProc` (the value from the server-side map) instead of raw user input `param`, ensuring only authorized procedure names reach the query.
- Added explicit `IllegalArgumentException` when procedure is not in the allowlist, providing clear error handling instead of silently using untrusted input.
- Return type and error handling chain (`throws ServletException`) remain unchanged; the exception propagates normally.
