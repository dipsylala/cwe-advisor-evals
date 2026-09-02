## Verdict
SQL injection vulnerability confirmed. The `accountId` and `status` parameters are concatenated directly into the SQL query string without parameterization, allowing an attacker to inject arbitrary SQL code.

## Source
Line 20 in `OrderMaintenanceRepository.cs`. The `ArchiveOrdersAsync` method builds a SQL command by interpolating user-supplied `accountId` and `status` strings directly into the query (lines 17-18), then passes this string to `ExecuteSqlRawAsync()`.

An attacker controlling `accountId` or `status` can inject SQL syntax. For example, `accountId = "' OR '1'='1"` would transform the query into:
```
UPDATE Orders SET Archived = 1 WHERE AccountId = '' OR '1'='1' ...
```
This executes unintended logic against the database.

## Fix
Replace `ExecuteSqlRawAsync()` with `ExecuteSqlInterpolated()` and use a `FormattableString` to allow Entity Framework Core to automatically parameterize the string-interpolated values:

```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    FormattableString sql =
        $"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} " +
        $"AND Status = {status} AND CreatedAt < {beforeUtc}";

    return _db.Database.ExecuteSqlInterpolatedAsync(sql);
}
```

## Explanation
`ExecuteSqlInterpolated()` is designed to work with C# `FormattableString` (created via `$"..."` syntax) and automatically converts interpolated values into SQL parameters. Each `{accountId}`, `{status}`, and `{beforeUtc}` becomes a parameterized placeholder (`@p0`, `@p1`, etc.) at the ADO.NET layer, preventing the values from being interpreted as SQL syntax.

The `beforeUtc` parameter was already intended as a parameter in the original code (note `@beforeUtc` literal in line 18) but was being passed incorrectly. `ExecuteSqlInterpolated()` unifies the approach: all interpolated values become parameters, and no raw string concatenation occurs.
