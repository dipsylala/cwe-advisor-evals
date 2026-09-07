## Verdict

SQL Injection (CWE-89): The `ArchiveOrdersAsync` method constructs a SQL query using string interpolation with unsanitized user inputs (`accountId` and `status`), enabling command injection through these parameters.

## Source

```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    var sql =
        $"UPDATE Orders SET Archived = 1 WHERE AccountId = '{accountId}' " +
        $"AND Status = '{status}' AND CreatedAt < @beforeUtc";

    return _db.Database.ExecuteSqlRawAsync(sql, beforeUtc);
}
```

The `accountId` and `status` parameters originate from untrusted user input via the HTTP request (ArchiveController) and are directly interpolated into the SQL string without parameterization. An attacker can inject SQL by providing values like `' OR '1'='1` or `'; DROP TABLE Orders; --`.

## Fix

```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    FormattableString sql =
        $"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} " +
        $"AND Status = {status} AND CreatedAt < {beforeUtc}";

    return _db.Database.ExecuteSqlRawAsync(sql);
}
```

## Explanation

EF Core's `ExecuteSqlRawAsync` has two overloads: one for `string` (dangerous when using string interpolation) and one for `FormattableString` (safe). When you pass a `FormattableString` to `ExecuteSqlRawAsync`, the method automatically converts the interpolated expressions into SQL parameters and removes the single quotes around the parameter placeholders.

The key changes:
1. Declare `sql` as `FormattableString` instead of `string`, which triggers the safe parameterization path.
2. Remove the single quotes around interpolation expressions: `'{accountId}'` becomes `{accountId}`.
3. Pass the FormattableString directly to `ExecuteSqlRawAsync` (no explicit parameter array needed; EF Core extracts and passes them).
4. All three parameters (`accountId`, `status`, `beforeUtc`) are now parameterized, eliminating SQL injection risk.

This preserves the query semantics while ensuring values are safely separated from the SQL syntax.
