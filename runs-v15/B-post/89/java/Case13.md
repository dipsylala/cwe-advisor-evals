## Verdict

Exploitable

## Source

Line 8-12 in Case13A.java: The `handle()` method receives data from a test case (hardcoded as "foo" in the test), which is passed to `Case13B.handleSink()`. In production, this would originate from user input via HTTP request parameters.

## Fix

**Vulnerable code (Case13B.java, line 21-28):**
```java
sqlStatement = dbConnection.createStatement();

resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

**Fixed code:**
```java
String query = "select * from users where name=?";
PreparedStatement pstmt = dbConnection.prepareStatement(query);
pstmt.setString(1, data);
resultSet = pstmt.executeQuery();
```

Additionally, update the resource cleanup in the finally block to close `pstmt` instead of `sqlStatement`, or change the variable declaration from `Statement sqlStatement` to `PreparedStatement pstmt` and update all references accordingly.

## Explanation

The vulnerability arises from directly concatenating user input into the SQL query string without any parameterization. An attacker can inject SQL metacharacters (such as `' OR '1'='1`) to manipulate the query logic. The fix replaces string concatenation with a parameterized query using prepared statements and placeholders (`?`). The untrusted `data` parameter is bound as a value using `setString()`, which ensures it is always treated as data rather than executable SQL code. This is the primary defense against SQL injection in Java and is enforced by the JDBC API itself—the SQL structure is fixed at prepare time, before any user input is incorporated.

## Behaviour changes

The prepared statement approach preserves the original sink contract:
- **Returns**: Still returns a `ResultSet` as before, processed identically by the existing code
- **Arguments**: The query string no longer includes user input; instead, the parameter is bound separately via `setString()`
- **Exception handling**: `SQLException` handling remains unchanged; `executeQuery()` on a `PreparedStatement` throws the same exceptions as `Statement.executeQuery(String)`
- **Resource cleanup**: Both `Statement` and `PreparedStatement` implement `AutoCloseable` and have identical `close()` semantics, so the existing finally block continues to work

No behaviour changes occur beyond closing the injection vulnerability.
