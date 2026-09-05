## Verdict

exploitable

## Source

Route parameter `ownerName` from `[HttpDelete("by-owner/{ownerName}")]` - user-controlled input from the URL path.

## Fix

**Vulnerable code (line 33):**
```csharp
command.CommandText = string.Format("DELETE FROM widgets WHERE owner = '{0}'", ownerName);
rowsDeleted = command.ExecuteNonQuery();
```

**Fixed code:**
```csharp
command.CommandText = "DELETE FROM widgets WHERE owner = @ownerName";
command.Parameters.Add("@ownerName", SqlDbType.NVarChar).Value = ownerName;
rowsDeleted = command.ExecuteNonQuery();
```

## Explanation

The vulnerability arises from concatenating the `ownerName` parameter directly into the SQL query string using `string.Format()`. An attacker can inject SQL by passing values like `' OR '1'='1` in the URL to manipulate the query logic. The fix replaces string concatenation with a parameterized query, where the untrusted `ownerName` is passed as a separate parameter with an explicit type (`SqlDbType.NVarChar`). This ensures the value is always treated as data, not as executable SQL code, preventing SQL injection attacks.

## Behaviour changes

- `CommandText` now contains a static SQL template with a placeholder `@ownerName` instead of the interpolated user value
- A parameter assignment line is added before `ExecuteNonQuery()` to bind the user input to the parameter
- The overall functionality remains identical: the DELETE query still filters by owner name
- No change to the return value or error handling contract of `ExecuteNonQuery()`
