## Verdict

Exploitable. The `owner` query parameter is concatenated directly into an SQL string without sanitization or parameterization, allowing an attacker to inject SQL fragments. For example, the input `' OR '1'='1` transforms the query into a tautology that returns all accounts rather than filtering by owner.

## Source

User-supplied query parameter `owner` from line 19: `[FromQuery] string owner`

## Fix

**Vulnerable code (lines 24-28):**
```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = '" + owner + "'";
using var command = new SqlCommand(sql, connection);

// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
using var reader = command.ExecuteReader();
```

**Fixed code:**
```csharp
string sql = "SELECT AccountId, Balance FROM Accounts WHERE Owner = @owner";
using var command = new SqlCommand(sql, connection);
command.Parameters.Add("@owner", SqlDbType.NVarChar).Value = owner;
using var reader = command.ExecuteReader();
```

## Explanation

Replace string concatenation with a parameterized query. The placeholder `@owner` stands in for the value, and the `Parameters.Add()` call binds the `owner` input as a typed parameter. The database driver treats the parameter value as data, not as executable SQL syntax, eliminating the injection vector. The `SqlDbType.NVarChar` explicit type is preferred over `AddWithValue()` inference for clarity and plan stability, and the `NVarChar` type is appropriate for string data in SQL Server. No size argument is required; `NVarChar` is variable-length and accepts the full value.

## Behaviour changes

- The SQL query uses a parameterized placeholder `@owner` instead of concatenated input, ensuring the user value is treated as data rather than code.
- A parameter binding statement is added before query execution to register the `owner` value with the command object.
- The parameter is explicitly typed as `SqlDbType.NVarChar`, which is appropriate for string comparisons in SQL Server's NVARCHAR column type.

These changes preserve the original sink contract: `ExecuteReader()` still executes the query and returns the same result set when the query logic is identical. The only runtime difference is that an SQL injection payload is now treated as a literal string value, not as query structure.
