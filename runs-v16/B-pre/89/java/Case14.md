## Verdict

Not exploitable. The code correctly uses parameterized queries with prepared statements.

## Source

`Case14A.java`, line 15: `data = request.getParameter("name");`

User-controlled input from HTTP request parameter `name`.

## Fix

No fix required. The existing code is secure.

## Explanation

The data path is:
1. **Source**: User input via `request.getParameter("name")` in Case14A
2. **Transmission**: Passed as parameter to `Case14B.handleSink(data, ...)`
3. **Sink**: Used in Case14B at line 25-26

The sink implements the safe pattern correctly:
```java
sqlStatement = dbConnection.prepareStatement("select * from users where name=?");
sqlStatement.setString(1, data);
```

The SQL string is a static literal containing a `?` placeholder. The untrusted `data` is bound to this placeholder via `setString()`, which ensures it is treated as a data value, not as SQL syntax. Parameterized queries with placeholder binding break the connection between user input and SQL structure, preventing SQL injection regardless of the input content. An attacker cannot inject SQL commands through this parameter.

## Behaviour changes

None. The code is already secure and requires no modification.
