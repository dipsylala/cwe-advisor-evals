## Verdict

Real vulnerability confirmed. The `owner` query parameter (untrusted user input) is concatenated directly into the SQL query string without parameterization, enabling SQL injection.

## Source

Line 19: `[FromQuery] string owner` – untrusted user-supplied data from query parameter.

## Fix

Replace string concatenation with a parameterized query. Change lines 24–28:

**Before:**
```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = '" + owner + "'";
using var command = new SqlCommand(sql, connection);

// SAST FINDING: CWE-89...
using var reader = command.ExecuteReader();
```

**After:**
```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @owner";
using var command = new SqlCommand(sql, connection);
command.Parameters.Add("@owner", SqlDbType.NVarChar).Value = owner;

// SAST FINDING: CWE-89...
using var reader = command.ExecuteReader();
```

The key changes:
1. Replace concatenation with a placeholder `@owner` in the SQL string
2. Bind the untrusted `owner` value as a parameter via `command.Parameters.Add()` with explicit type `SqlDbType.NVarChar`
3. Assign the value to the parameter's `.Value` property

## Explanation

Parameterized queries ensure user input is always treated as data, never as executable SQL structure. The database driver separates the query logic (the SQL string with placeholders) from the data values (passed as parameters), preventing the attacker from manipulating the query syntax. The `SqlCommand.Parameters.Add()` method with an explicit `SqlDbType` is the standard C# safe pattern for this weakness. This fix closes the injection point while preserving the query's functionality – it still retrieves accounts matching the `owner` value, now safely.

## Behaviour changes

The application continues to return the same result set (matching accounts), with no change to return types, error handling, or side effects. `ExecuteReader()` still produces a `SqlDataReader` object as before. The parameter binding is transparent to calling code.
