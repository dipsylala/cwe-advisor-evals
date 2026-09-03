## Verdict

Exploitable

## Source

User-controlled input from the HTTP request body in `ArchiveController` at line 19: `request.AccountId` and `request.Status` are passed unsanitized through the call chain to the database layer.

## Fix

**Vulnerable code:**

```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    var sql =
        $"UPDATE Orders SET Archived = 1 WHERE AccountId = '{accountId}' " +
        $"AND Status = '{status}' AND CreatedAt < @beforeUtc";

    return _db.Database.ExecuteSqlRawAsync(sql, beforeUtc);
}
```

The parameters `accountId` and `status` are directly interpolated into the SQL string. An attacker can inject SQL by crafting a payload like `accountId = "' OR '1'='1"` to break out of the quoted context and inject arbitrary SQL commands.

**Fixed code:**

```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    FormattableString sql = $"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} AND Status = {status} AND CreatedAt < {beforeUtc}";
    
    return _db.Database.ExecuteSqlAsync(sql);
}
```

## Explanation

The fix uses Entity Framework Core's `ExecuteSqlAsync()` method with a `FormattableString` parameter. When you use string interpolation with variables in curly braces and pass the resulting `FormattableString` to `ExecuteSqlAsync()`, Entity Framework Core automatically extracts the interpolated values and binds them as database parameters. This ensures that user-supplied values are treated as data, not as executable SQL code. All three values (`accountId`, `status`, and `beforeUtc`) are now properly parameterized, preventing SQL injection regardless of their content.

## Behaviour changes

- Changed from `ExecuteSqlRawAsync()` to `ExecuteSqlAsync()`: both are non-query async methods that return `Task<int>` representing rows affected, so the return type and caller contract remain identical
- Changed from concatenating a raw SQL string to using a parameterized `FormattableString`: this is the core security fix that eliminates the injection vector
- The `@beforeUtc` parameter is now part of the parameterized interpolated string instead of being passed separately: `ExecuteSqlAsync()` automatically handles all parameters extracted from the `FormattableString`, so the parameter passing changes from a varargs array to implicit extraction from the formatted string
- Removed manual parameter binding for `beforeUtc` (previously passed as the second argument to `ExecuteSqlRawAsync()`): `ExecuteSqlAsync()` extracts parameters automatically from the `FormattableString`
