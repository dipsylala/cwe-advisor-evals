## Verdict
SQL injection vulnerability confirmed. The `owner` query parameter is concatenated directly into the SQL command string without parameterization, allowing an attacker to inject arbitrary SQL syntax.

## Source
Line 24: `string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = '" + owner + "'";`

The untrusted `owner` parameter (from `[FromQuery] string owner`) flows directly into SQL command construction via string concatenation.

## Fix
Replace string concatenation with parameterized query:

```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @Owner";
using var command = new SqlCommand(sql, connection);
command.Parameters.AddWithValue("@Owner", owner);
using var reader = command.ExecuteReader();
```

## Explanation
String concatenation embeds user input directly into SQL syntax, where special characters like single quotes can break out of the intended string literal and inject arbitrary SQL logic. Parameterized queries separate the SQL command structure from the data values; the database driver handles escaping and ensures user input is treated as literal data, not SQL syntax. This is the standard and most effective defence against SQL injection in .NET.
