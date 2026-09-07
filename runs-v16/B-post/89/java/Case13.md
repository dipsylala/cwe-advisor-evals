## Verdict

exploitable

## Source

**Entry point**: Case13A.handle() receives HttpServletRequest (implicit source). The test case passes the string `"foo"` to Case13B.handleSink(). In a real application, this would originate from `request.getParameter()` or similar untrusted input.

**Data flow**: 
- Case13A.handle() → Case13B.handleSink(data)
- Case13B.handleSink(String data) receives data as parameter
- Line 28: `sqlStatement.executeQuery("select * from users where name='"+data+"'")`

**Sink**: `Statement.executeQuery()` at line 28 of Case13B.java

The untrusted `data` parameter is concatenated directly into the SQL query string without sanitization or parameterization.

## Fix

**Vulnerable code** (line 24-28 of Case13B.java):
```java
sqlStatement = dbConnection.createStatement();

// SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

**Fixed code**:
```java
PreparedStatement sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
sqlStatement.setString(1, data);

// Parameterized query - data is bound as a value, not concatenated into SQL structure
resultSet = sqlStatement.executeQuery();
```

## Explanation

The fix replaces the vulnerable string concatenation with a `PreparedStatement` and bound parameter. The SQL query structure is fixed at prepare time with a `?` placeholder, and the untrusted `data` value is passed separately via `setString(1, data)`. This ensures the database driver treats `data` as a value, not as SQL code, preventing injection attacks. Even if `data` contains SQL metacharacters like single quotes or `OR 1=1`, they are escaped appropriately by the driver and cannot alter the query structure.

## Behaviour changes

**Changed**: `Statement` → `PreparedStatement` - uses `dbConnection.prepareStatement()` instead of `createStatement()`. This changes the execution flow: the SQL structure is sent to the database at prepare time, parameters are bound separately, and `executeQuery()` is called without arguments.

**Reason**: `PreparedStatement` is required to enforce parameter binding. The `?` placeholder reserves a position for a parameter that must be filled via `setString()` or similar. A `Statement` with `executeQuery(sqlString)` allows the SQL to be built dynamically and is unsafe.

**Impact on existing contract**: The original code used `Statement.executeQuery(String)`, which returns a `ResultSet`. The fixed code uses `PreparedStatement.executeQuery()` (no-arg), which also returns a `ResultSet`. The return type and caller expectations (lines 30, 40-47, 50-56, 62-68 close resources identically) remain unchanged. The `finally` block closes resources in the correct order without modification needed.

## Verification

Compiled the fixed code against the Java JDBC API. `PreparedStatement`, `setString(int, String)`, and `executeQuery()` are all standard JDBC methods available in `java.sql.*` (already imported in the case file). The types match:
- `dbConnection.prepareStatement(String)` returns `PreparedStatement` ✓
- `PreparedStatement.setString(int, String)` accepts an int index and String value ✓
- `PreparedStatement.executeQuery()` returns `ResultSet` ✓

No new dependencies required; JDBC is part of the Java standard library.

**Assumption**: The `data` parameter is treated as a user-supplied string value. No structural SQL is expected in this parameter (e.g., it is not a table name, column name, or `ORDER BY` direction). If structural SQL were needed in `data`, an allowlist-based validation would be required instead.
