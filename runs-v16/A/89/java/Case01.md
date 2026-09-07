## Verdict

SQL Injection vulnerability confirmed on line 28. User-supplied data from `request.getParameter()` is concatenated directly into a SQL query string without parameterization, allowing an attacker to inject arbitrary SQL commands.

## Source

**File:** Case01B.java, line 28

```java
resultSet = sqlStatement.executeQuery("select * from users where name='"+data+"'");
```

The `data` parameter originates from `request.getParameter("name")` in Case01A.java and flows untrusted into the SQL query.

## Fix

Replace the string concatenation with a prepared statement:

```java
PreparedStatement preparedStatement = dbConnection.prepareStatement("select * from users where name=?");
preparedStatement.setString(1, data);
resultSet = preparedStatement.executeQuery();
```

Then update the finally block to close the `PreparedStatement` instead of the `Statement`:

```java
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
        if (preparedStatement != null)
        {
            preparedStatement.close();
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

The original code uses string concatenation to build the SQL query, which allows an attacker to break out of the string context by injecting SQL syntax. For example, an input of `' OR '1'='1` would transform the query to `select * from users where name='' OR '1'='1'`, returning all users regardless of the name filter.

Prepared statements separate the SQL structure from the data values. The `?` placeholder indicates where data will be inserted, and `setString()` ensures the value is treated as literal data, not executable SQL code. The JDBC driver handles proper escaping automatically. This approach is immune to SQL injection because the SQL structure is fixed and user input cannot alter the query's logical meaning.
