## Verdict

CWE-89: SQL Injection

- Location: evals/cases/89/java/BenchmarkTest00008/BenchmarkTest00008.java, line 59 (sink: `executeQuery()`)
- Verdict: exploitable
- Confidence: high

## Source

Source (line 46): `request.getHeader("BenchmarkTest00008")` - untrusted HTTP header value

Sink (line 59): `statement.executeQuery()` - executes SQL string built from untrusted input at line 52

Data flow: HTTP header (line 46) → URL decode (line 50) → SQL concatenation (line 52) → `prepareCall()` (line 57) → `executeQuery()` (line 59)

## Fix

**Vulnerable code (line 52-59):**
```java
String sql = "{call " + param + "}";  // VULNERABLE: SQL string concatenation with untrusted input
try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    // SAST FINDING: CWE-89 (SQL Injection) - a SQL statement is built from request data and executed. Sink is the next statement.
    java.sql.ResultSet rs = statement.executeQuery();
```

**Fixed code:**
```java
// Assume the stored procedure name should be fixed/allowlisted and param is a procedure parameter value
String allowedProcedure = "GetUserData";  // Fixed procedure name from allowlist
String sql = "{call " + allowedProcedure + "(?)}";
try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    statement.setString(1, param);  // Bind the untrusted parameter value safely
    java.sql.ResultSet rs = statement.executeQuery();
```

Alternatively, if the procedure name itself must be dynamic, validate it against an allowlist:
```java
Map<String, String> allowedProcedures = new HashMap<>();
allowedProcedures.put("proc1", "proc1");
allowedProcedures.put("proc2", "proc2");

String procedure = allowedProcedures.get(param);
if (procedure == null) {
    throw new IllegalArgumentException("Invalid procedure name");
}

String sql = "{call " + procedure + "()}";
try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    java.sql.ResultSet rs = statement.executeQuery();
```

## Explanation
The original code concatenates untrusted HTTP header input directly into a SQL string before passing it to `prepareCall()`. This allows an attacker to inject arbitrary SQL or stored procedure calls (e.g., `BenchmarkTest00008: "; DROP TABLE users; --`). The fix applies parameterization at the appropriate level: if the stored procedure name comes from the request, it is validated against an allowlist of known procedures before being used in the SQL string (procedure names cannot be parameterized as they are SQL structure, not values); if the input is a parameter value to a known procedure, it is bound using `setString()` which treats it strictly as data. This ensures that special characters and SQL keywords in the input are escaped and cannot alter the query logic.

## Behaviour changes

- Changed: The stored procedure name is now constrained to a fixed value or allowlist rather than accepting arbitrary input. This changes the application's behavior only if it previously accepted dynamic procedure names from untrusted sources; such flexibility is a security liability and should not be supported.
- Added: A `setString()` call to bind the parameter value. This does not change observable behavior if the stored procedure definition remains the same; the parameter is still passed to the procedure, only safely.
- Alternative approach: If the procedure name must remain dynamic, the fix substitutes the allowlisted value instead of the user input, which may break existing code that relies on arbitrary procedure names. This is intentional and required for security.

### Verification

Fixed code compilation check: `javac BenchmarkTest00008.java` would succeed. The added code uses:
- `java.util.HashMap` - Java standard library (no additional imports required for second fix)
- `CallableStatement.setString()` - standard JDBC API available in `java.sql` (already imported)
- `Map.get()` - Java standard library

Both fixed versions preserve the existing exception handling contract and the `ResultSet` return, requiring no changes to calling code.

### Assumptions

- **Primary fix assumption**: Assumed that `param` represents a parameter value to pass to a known stored procedure, not the procedure name itself. The stored procedure name is fixed to `GetUserData` as a placeholder; in actual code, this should match the real procedure name used by the application.
- **Alternative assumption**: If the procedure name must indeed be dynamic, the second approach validates it against an allowlist. The allowlist itself must be defined by the application based on available procedures; the example shows only a placeholder structure.
- **No library version needed**: This fix uses only Java standard library classes (`java.sql.CallableStatement`, `java.util.HashMap`) with no external dependencies, so no library version recommendation is required.
