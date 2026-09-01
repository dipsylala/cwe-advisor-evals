## Verdict
Exploitable

## Source
Line 19: `[FromQuery] string owner` - attacker-controlled query parameter

## Fix

**Vulnerable code:**
```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = '" + owner + "'";
using var command = new SqlCommand(sql, connection);

// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
using var reader = command.ExecuteReader();
```

**Fixed code:**
```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @Owner";
using var command = new SqlCommand(sql, connection);
command.Parameters.Add("@Owner", SqlDbType.NVarChar).Value = owner;

using var reader = command.ExecuteReader();
```

## Explanation

The vulnerability occurs because the `owner` query parameter is concatenated directly into the SQL string without parameterization. An attacker can inject SQL metacharacters—for example, `' OR '1'='1`—to manipulate the query logic and bypass authentication or retrieve unauthorized data. The fix replaces string concatenation with a parameterized query using `SqlCommand.Parameters.Add()` with an explicit `SqlDbType.NVarChar`. This ensures the user input is always treated as data, not as executable SQL code. The database driver handles escaping automatically, and SQL injection becomes impossible regardless of what characters the input contains.

## Behaviour changes
None. The parameterized query returns the same `SqlDataReader` object and executes with identical semantics to the original code. The `SqlCommand.ExecuteReader()` sink contract is preserved: it still returns a reader the caller can iterate through, still throws `SqlException` on database errors, and still operates under the same connection and transaction scope.
