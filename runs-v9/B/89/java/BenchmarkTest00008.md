## Verdict

- **CWE ID:** CWE-89 (SQL Injection)
- **Location:** `BenchmarkTest00008.java`, line 59 (sink); the tainted SQL text is assembled at line 52
- **Verdict:** exploitable
- **Confidence:** medium (lowered by an assumption noted below)

## Source

`request.getHeader("BenchmarkTest00008")` (line 45-46), URL-decoded at line 50 via `java.net.URLDecoder.decode(param, "UTF-8")`. An HTTP request header is fully attacker-controlled, and URL-decoding does not neutralize SQL metacharacters — it only reverses percent-encoding, so any payload the attacker percent-encodes reaches `param` unmodified from a SQL Injection perspective.

Data flow: `request.getHeader(...)` -> `param` -> `sql = "{call " + param + "}"` (line 52) -> `connection.prepareCall(sql)` (line 57) -> `statement.executeQuery()` (line 59, the reported sink).

Unlike most injection findings, `param` here is not slotted into a value position of a fixed query — it *is* the entire contents of the JDBC call-escape syntax between `{call ` and `}`. The attacker fully controls which stored procedure (if any) is invoked and with what literal arguments, so this is a structure-position injection, not a value-position one.

## Fix

No third-party library is involved — `java.sql` is part of the JDK, so there is no dependency/version recommendation for this fix.

**Vulnerable code (lines 44-59):**

```java
String param = "";
if (request.getHeader("BenchmarkTest00008") != null) {
    param = request.getHeader("BenchmarkTest00008");
}

// URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
param = java.net.URLDecoder.decode(param, "UTF-8");

String sql = "{call " + param + "}"; // VULNERABLE: entire call statement built from request data

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    // SAST FINDING: CWE-89 (SQL Injection) - a SQL statement is built from request data and executed.
    java.sql.ResultSet rs = statement.executeQuery();
    org.owasp.benchmark.helpers.DatabaseHelper.printResults(rs, sql, response);
```

**Fixed code:**

```java
// Fixed, server-controlled set of procedures this endpoint is permitted to invoke.
// Populate this with the actual procedure names this endpoint is meant to call —
// the placeholder keys/values below stand in for the real business mapping.
private static final java.util.Map<String, String> ALLOWED_PROCEDURES =
        java.util.Map.of(
                "getItem", "GetItemProc",
                "getUser", "GetUserProc");

...

String param = "";
if (request.getHeader("BenchmarkTest00008") != null) {
    param = request.getHeader("BenchmarkTest00008");
}

// URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
param = java.net.URLDecoder.decode(param, "UTF-8");

// Resolve the caller-supplied identifier against a fixed allowlist and use the
// allowlist's own canonical value downstream — never the raw request value.
String procedureName = ALLOWED_PROCEDURES.get(param);
if (procedureName == null) {
    throw new ServletException("Unknown or unauthorized procedure requested");
}
String sql = "{call " + procedureName + "}";

try {
    java.sql.Connection connection =
            org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.CallableStatement statement = connection.prepareCall(sql);
    java.sql.ResultSet rs = statement.executeQuery();
    org.owasp.benchmark.helpers.DatabaseHelper.printResults(rs, sql, response);
```

## Explanation

`param` occupies a structure position (the callable-statement target itself), not a value position, so a JDBC `?` placeholder cannot fix it — `CallableStatement` placeholders bind argument *values* inside an already-fixed `{call procedure_name(...)}` text; the procedure name itself must be static SQL text supplied by the application, never the caller. The fix therefore applies the knowledge base's identifier-allowlist pattern: the raw header value is looked up in a fixed, server-controlled map of permitted procedure names, and the SQL text is built only from the map's own value, never from the attacker's string. Any value that isn't a recognized key is rejected before a `Connection` is even touched. This closes the injection because no attacker-supplied byte ever reaches the SQL text — the only thing derived from `param` is which pre-approved lookup succeeded.

## Behaviour changes

- The endpoint no longer executes an arbitrary caller-specified call statement; it now accepts only identifiers present in `ALLOWED_PROCEDURES` and calls the corresponding fixed procedure name. A request whose header value is not one of the allowlisted keys now fails fast with a `ServletException`, where previously it would have been sent to the database as-is (typically erroring there, or — the vulnerability itself — succeeding as attacker-chosen SQL). This behavioural narrowing is the fix, not an incidental side effect: the original code's willingness to run any client-supplied call text is the weakness being closed.
- `ALLOWED_PROCEDURES` uses placeholder keys/values (`"getItem"`/`"GetItemProc"`, `"getUser"`/`"GetUserProc"`) because the actual set of procedures this endpoint is meant to expose is not recoverable from this file alone (it is a single isolated servlet with no accompanying schema or spec). The developer must replace these with the real permitted procedure names before deploying; the mechanism (allowlist lookup, canonical value used downstream) is the load-bearing part of the fix and does not change once real names are substituted.
- All other behaviour is unchanged: `doGet` still delegates to `doPost`, the response content type, header retrieval, URL-decoding, `executeQuery()`/`printResults()` call shape, and the existing `SQLException` handling (`hideSQLErrors` short response vs. wrapping in `ServletException`) are all preserved exactly as in the original.

**Assumption:** the header value is intended to select which stored procedure to invoke (consistent with the bare `{call <param>}` syntax, which names a procedure with no arguments). Confidence is medium rather than high because the real set of permitted procedure names is not present in the provided file and had to be represented with placeholders.
