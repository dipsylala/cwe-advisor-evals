## Verdict

Real - confirmed exploitable SQL injection through string concatenation.

## Source

`owner` parameter from `[FromQuery]` on line 19 (untrusted HTTP query parameter).

## Fix

Replace line 22's string concatenation with a parameterized query:

**Vulnerable code (line 22):**
```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = '" + owner + "'";
using var command = new SqlCommand(sql, connection);
```

**Fixed code:**
```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @Owner";
using var command = new SqlCommand(sql, connection);
command.Parameters.Add("@Owner", SqlDbType.NVarChar).Value = owner;
```

The parameter is declared with an explicit type (`SqlDbType.NVarChar`) and assigned its value on the returned parameter object. This ensures the `owner` input is always treated as literal data, not as query syntax.

## Explanation

The original code concatenates the untrusted `owner` query parameter directly into the SQL string. An attacker can inject SQL metacharacters (e.g., `' OR '1'='1`) to manipulate the query logic and retrieve unauthorized data.

The fix uses a parameterized query with `SqlCommand.Parameters.Add()`, which transfers user input handling from string concatenation to the database driver's parameter binding. The driver ensures the parameter value is always interpreted as a string literal, never as SQL syntax, regardless of its content. This is the primary defence against SQL injection in C#/SQL Server contexts.

## Behaviour changes

- The SQL query string is now constructed once with a placeholder (`@Owner`) rather than being rebuilt for each request value. This also improves performance through query plan caching.
- The `owner` value is no longer embedded in the SQL text; it is transmitted separately to the database engine as a parameter, making the query structure immutable.
- Error messages will no longer expose the user's input value in the query text if an exception occurs (defence-in-depth).
- No change to the return type, control flow, or result set - the query logic is identical for legitimate input.
