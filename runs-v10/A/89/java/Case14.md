## Verdict
Not vulnerable. The code properly mitigates SQL injection through parameterized query defense.

## Source
Case14A.java, line 15: `data = request.getParameter("name");` provides untrusted HTTP request input that flows to the SQL execution sink in Case14B.

## Fix
The vulnerability is already mitigated. Case14B.java uses parameterized queries (prepared statements with `?` placeholders and `setString()` parameter binding) to safely execute the SQL query:

```java
sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
sqlStatement.setString(1, data);
resultSet = sqlStatement.executeQuery();
```

## Explanation
Parameterized queries separate SQL structure from user-supplied data. The `?` placeholder marks where the parameter belongs, and `setString(1, data)` binds the user input as data, not as executable SQL. This ensures that even if `data` contains SQL metacharacters or complete SQL statements, they are treated as literal string values within the `name` column comparison. The SAST tool correctly identified the taint source (HTTP parameter) and traced it to the SQL sink (query execution), but the code already implements the standard, proven defense against SQL injection.
