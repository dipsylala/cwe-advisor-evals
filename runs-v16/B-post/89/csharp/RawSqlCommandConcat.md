## Verdict
Exploitable

## Source
User-controlled input from `[FromQuery] string owner` parameter on line 19, passed to the HTTP GET endpoint.

## Fix

**Vulnerable code (line 24):**
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

## Explanation
The vulnerability exists because the `owner` query parameter is concatenated directly into the SQL string on line 24. This allows an attacker to inject arbitrary SQL by providing input like `'; DROP TABLE Accounts; --`. The fix replaces string concatenation with a parameterized query using `SqlCommand.Parameters.Add()` with an explicit `SqlDbType.NVarChar` type and the parameter placeholder `@Owner`. This ensures the user input is treated as a data value, not as executable SQL, and is the primary defence against SQL injection in C#.

## Behaviour changes
None. The parameterized query executes the same SELECT statement, returns the same `SqlDataReader`, and the result collection logic is unchanged. The `.ExecuteReader()` call on line 28 remains unaffected.
