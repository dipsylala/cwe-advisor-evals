## Verdict
exploitable

## Source
Untrusted data enters at `e:/Github/cwe-advisor/evals/cases-v2/Case01/Case01A.java` line 15, `data = request.getParameter("name")`, an attacker-controlled HTTP request parameter. It is passed unmodified at line 17 into `Case01B.handleSink(data, request, response)`, and reaches the sink at `e:/Github/cwe-advisor/evals/cases-v2/Case01/Case01B.java` line 28, where it is concatenated into a SQL string executed by `Statement.executeQuery`. No validation, encoding, or sanitisation occurs anywhere along the path.

## Fix
```java
// Case01B.java - handleSink

Connection dbConnection = null;
PreparedStatement sqlStatement = null;
ResultSet resultSet = null;

try
{
    dbConnection = IO.getDBConnection();
    sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
    sqlStatement.setString(1, data);

    resultSet = sqlStatement.executeQuery();

    IO.writeLine(resultSet.getRow());
}
catch (SQLException exceptSql)
{
    IO.logger.log(Level.WARNING, "Error getting database connection", exceptSql);
}
finally
{
    try
    {
        if (resultSet != null)
        {
            resultSet.close();
        }
    }
    catch (SQLException exceptSql)
    {
        IO.logger.log(Level.WARNING, "Error closing ResultSet", exceptSql);
    }

    try
    {
        if (sqlStatement != null)
        {
            sqlStatement.close();
        }
    }
    catch (SQLException exceptSql)
    {
        IO.logger.log(Level.WARNING, "Error closing PreparedStatement", exceptSql);
    }

    try
    {
        if (dbConnection != null)
        {
            dbConnection.close();
        }
    }
    catch (SQLException exceptSql)
    {
        IO.logger.log(Level.WARNING, "Error closing Connection", exceptSql);
    }
}
```

## Explanation
The servlet reads the `name` request parameter and hands it straight to a helper that builds a SQL query by string concatenation, so an attacker controls the text of the statement inside the quoted literal and can terminate the string and append arbitrary SQL clauses. The fix replaces the `Statement` with a `PreparedStatement` carrying a `?` placeholder and binds the value with `setString`, so the driver sends the query text and the parameter value separately and the database can never reinterpret user input as SQL syntax. The variable's declared type and the `close()` in the `finally` block change accordingly; no other behaviour is altered, and the query still returns the same rows for legitimate input. Escaping or blacklisting characters would not be an equivalent defence here, because it depends on the exact quoting context and the database's escape rules rather than on a structural separation of code and data.
