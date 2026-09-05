## Verdict

Exploitable. The `data` parameter is directly concatenated into an SQL query string without parameterization, allowing SQL injection.

## Source

Data originates in `Case13A.java` line 15 as `data = "foo"` and flows through the parameter `handleSink(String data, ...)` to the sink.

## Fix

**Vulnerable code (Case13B.java, lines 17-28):**

```java
Connection dbConnection = null;
Statement sqlStatement = null;
ResultSet resultSet = null;

try
{
    dbConnection = IO.getDBConnection();
    sqlStatement = dbConnection.createStatement();

    
    // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
    resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

**Fixed code:**

```java
Connection dbConnection = null;
PreparedStatement sqlStatement = null;
ResultSet resultSet = null;

try
{
    dbConnection = IO.getDBConnection();
    sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
    sqlStatement.setString(1, data);

    resultSet = sqlStatement.executeQuery();
```

## Explanation

The fix replaces string concatenation with a parameterized query using `PreparedStatement`. Instead of `createStatement()` which accepts a raw SQL string, we use `prepareStatement()` with a `?` placeholder for the user-supplied value. The `setString()` method then binds the data to the first parameter, ensuring it is treated as data rather than executable SQL. This eliminates the injection vector by separating query structure from data values. The type of `sqlStatement` changes from `Statement` to `PreparedStatement` to reflect the parameterized nature of the prepared statement, but the return type and usage of `executeQuery()` remain the same.

## Behaviour changes

The change from `Statement.executeQuery(String)` to `PreparedStatement.executeQuery()` does not alter the externally visible contract: both return a `ResultSet`, both throw `SQLException` on error, and the result is used identically downstream. The resource-cleanup code in the `finally` block remains unchanged, as `PreparedStatement` is a subtype of `Statement`. No other behavioral difference is introduced.
