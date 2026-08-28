## Verdict
exploitable

## Source
Untrusted data enters at `evals/cases-v2/Case01/Case01A.java:15` via `request.getParameter("name")` in `Case01A.handle(HttpServletRequest, HttpServletResponse)`. The value is assigned to `data` and passed unchanged to `new Case01B().handleSink(data, request, response)` at `Case01A.java:17`. Inside `evals/cases-v2/Case01/Case01B.java`, the parameter `data` is concatenated directly into the SQL string at line 28 and executed by `Statement.executeQuery(...)`. No validation, encoding, or parameter binding occurs anywhere on the path.

## Fix
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

            IO.writeLine(resultSet.getRow());
        }
```

## Explanation
The query text is built by string concatenation, so an attacker controlling the `name` request parameter controls SQL syntax rather than just a value - a payload such as `' OR '1'='1` closes the quoted literal and rewrites the `WHERE` clause. Replacing the `Statement` with a `PreparedStatement` whose SQL carries a `?` placeholder, and supplying the request value through `setString(1, data)`, sends the query structure to the database separately from the value, so the input is bound as data and can never alter the parsed statement. The declaration of `sqlStatement` changes from `Statement` to `PreparedStatement` and the no-argument `executeQuery()` overload is used; the surrounding connection handling and the `finally` cleanup block are unchanged. Input validation on `name` remains worthwhile as a secondary layer, but parameterization is what closes the injection.
