## Verdict

CONFIRMED. The `name` parameter from the HTTP request is directly concatenated into a SQL query without parameterization, enabling SQL injection.

## Source

Case01A.java:15 — `request.getParameter("name")` returns untrusted user input.

Data flows to Case01B.java:28 where it is used in string concatenation to build a SQL query.

## Fix

**Vulnerable code (Case01B.java:24-28):**

```java
sqlStatement = dbConnection.createStatement();

// SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

**Fixed code:**

```java
PreparedStatement preparedStatement = dbConnection.prepareStatement("select * from users where name=?");
preparedStatement.setString(1, data);

resultSet = preparedStatement.executeQuery();
```

Replace the `Statement` with a `PreparedStatement` that uses a `?` placeholder for the `name` value. The untrusted `data` parameter is bound separately via `setString()`, ensuring it is treated as a literal string value, not executable SQL.

Update the finally block to close the `PreparedStatement` instead of the generic `Statement`:

```java
try
{
    if (preparedStatement != null)
    {
        preparedStatement.close();
    }
}
catch (SQLException exceptSql)
{
    IO.logger.log(Level.WARNING, "Error closing PreparedStatement", exceptSql);
}
```

## Explanation

Parameterized queries are the standard defence against SQL injection in Java. The `PreparedStatement` parses the SQL structure once with the placeholder in place, then binds the user-supplied value separately. This ensures the input can never alter the query's logic — it is always treated as literal data within the `name` column comparison.

The fix preserves the existing behaviour: the query still searches the `users` table by name and returns the same `ResultSet`. The only change is how the parameter is passed: through parameter binding instead of string concatenation.

## Behaviour changes

- **Query structure**: Now uses parameterized `?` placeholder instead of concatenated string
- **Execution method**: `PreparedStatement` instead of generic `Statement`
- **Parameter binding**: `setString(1, data)` explicitly binds the user input
- **Resource cleanup**: Updated to close `PreparedStatement` instead of generic `Statement`
- **Security**: SQL structure is locked after parse; user input cannot modify query logic
- **No functional change**: Query results are identical for benign inputs; malicious payloads are now rejected
