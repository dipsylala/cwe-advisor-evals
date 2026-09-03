## Verdict

Exploitable. The data parameter flows untrusted from `HttpServletRequest.getParameter()` in Case02A through three intermediate pass-throughs (Case02B, Case02C) to the SQL sink in Case02D.handleSink() line 28, where it is concatenated directly into a query string passed to `Statement.executeQuery()`.

## Source

**Location:** evals/cases/89/java/Case02/Case02A.java, line 15

**Code:** `data = request.getParameter("name");`

The `data` variable receives untrusted user input from the HTTP request parameter `"name"`. This value is never validated or sanitized before being passed through the call chain.

## Fix

**Vulnerable code (Case02D.java, lines 17-28):**

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

    IO.writeLine(resultSet.getRow());
}
```

**Fixed code:**

```java
Connection dbConnection = null;
PreparedStatement sqlStatement = null;
ResultSet resultSet = null;

try
{
    dbConnection = IO.getDBConnection();
    String query = "select * from users where name=?";
    sqlStatement = dbConnection.prepareStatement(query);
    sqlStatement.setString(1, data);

    resultSet = sqlStatement.executeQuery();

    IO.writeLine(resultSet.getRow());
}
```

## Explanation

The fix replaces string concatenation with a `PreparedStatement` parameterized query. The original code builds the SQL string by concatenating the untrusted `data` parameter directly into the query, allowing an attacker to inject SQL syntax (for example, `' OR '1'='1`). The fixed code uses a placeholder (`?`) in the SQL string, then binds the user input as a typed parameter via `setString()`. This ensures the input is always treated as a string value, never as executable SQL code. The `PreparedStatement` also eliminates the need for the `"'"+data+"'"` wrapping—the database driver handles the quoting and escaping transparently. The method `executeQuery()` is called with no arguments (the prepared statement already carries the bound parameters) and returns the same `ResultSet` contract as the original, so downstream code is unaffected.

## Behaviour changes

- **Type change:** `Statement` → `PreparedStatement`. Both implement the same SQL execution contracts; no caller-visible behaviour change.
- **SQL string:** Moved from inline concatenation to a separate variable to clarify the parameterized structure. The query reaches the database server identical to the original in structure, but with separate parameter values.
- **Parameter binding:** Added `setString(1, data)` to bind the untrusted value as a typed SQL parameter. This is required; omitting it is a syntax error.
- **executeQuery() call:** Changed from `executeQuery(String)` to `executeQuery()` with no arguments, because the `PreparedStatement` already carries the query and parameters. Both return a `ResultSet` and throw the same `SQLException` on error; no change to error handling contract.
- **No changes to try/catch/finally logic:** Resource cleanup remains identical.
