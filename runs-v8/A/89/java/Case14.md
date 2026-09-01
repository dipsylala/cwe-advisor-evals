## Verdict
SQL injection vulnerability via untrusted HTTP request parameter flowing to database query execution.

## Source
Case14A.java line 15: `data = request.getParameter("name");` receives untrusted user input.

## Fix
Case14B.java lines 25-26 demonstrate the correct remediation:

```java
sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
sqlStatement.setString(1, data);
```

Replace direct string concatenation with a parameterized prepared statement using the `?` placeholder. Bind the untrusted data separately using `setString()` (or the appropriate type-specific setter: `setInt()`, `setBoolean()`, etc.).

The vulnerability is eliminated because the database driver parses the SQL structure first, then substitutes parameters as data values only—the untrusted input cannot alter the query's control flow or syntax.

## Explanation
Prepared statements with parameter binding prevent SQL injection by separating SQL syntax from data. The database engine parses the query template (`"select * from users where name=?"`) before any user data is introduced, then treats the bound parameter `data` strictly as a value, not executable code. 

Special characters, quotes, and SQL keywords in `data` are automatically escaped by the driver's type-specific setter. This is fundamentally safer than string concatenation or manual escaping because it makes injection syntactically impossible—the attacker's input cannot inject SQL commands.

Ensure all dynamic values in SQL queries use parameter binding, not concatenation.
