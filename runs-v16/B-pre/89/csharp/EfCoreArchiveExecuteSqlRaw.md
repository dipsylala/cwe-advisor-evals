## Verdict
Exploitable

## Source
`accountId` and `status` parameters passed to `ArchiveOrdersAsync()`

## Fix
**Vulnerable code:**
```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    var sql =
        $"UPDATE Orders SET Archived = 1 WHERE AccountId = '{accountId}' " +  // Direct interpolation—injectable
        $"AND Status = '{status}' AND CreatedAt < @beforeUtc";
    return _db.Database.ExecuteSqlRawAsync(sql, beforeUtc);
}
```

**Fixed code:**
```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    return _db.Database.ExecuteSqlInterpolatedAsync(
        $"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} AND Status = {status} AND CreatedAt < {beforeUtc}");
}
```

## Explanation
The original code builds SQL by concatenating user-supplied parameters directly into the query string using C# string interpolation. Entity Framework's `ExecuteSqlRawAsync()` executes this string as-is, allowing an attacker to inject SQL via `accountId` or `status`. The fix uses `ExecuteSqlInterpolatedAsync()`, which accepts a `FormattableString`. Entity Framework automatically wraps each interpolated value (`{accountId}`, `{status}`, `{beforeUtc}`) in a `DbParameter`, treating all values as data rather than SQL code. This prevents injection regardless of the input content.

## Behaviour changes
- **Method call**: Changed from `ExecuteSqlRawAsync(sql, beforeUtc)` to `ExecuteSqlInterpolatedAsync(FormattableString)`. The latter automatically extracts parameters from the interpolated string, so `beforeUtc` need not be passed separately.
- **Return type**: Identical—both return `Task<int>` (number of rows affected).
- **Parameterization scope**: Original parameterized only `beforeUtc`; fixed version parameterizes all three values (`accountId`, `status`, `beforeUtc`).
