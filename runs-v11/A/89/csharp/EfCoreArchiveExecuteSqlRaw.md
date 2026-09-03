## Verdict
SQL injection vulnerability confirmed. The `accountId` and `status` parameters are embedded directly into the SQL string using string interpolation, allowing an attacker to inject arbitrary SQL code. The `beforeUtc` parameter is correctly parameterized with the `@beforeUtc` placeholder, but the other two user inputs bypass parameterization entirely.

## Source
Lines 16-20 in OrderMaintenanceRepository.cs:
```csharp
var sql =
    $"UPDATE Orders SET Archived = 1 WHERE AccountId = '{accountId}' " +
    $"AND Status = '{status}' AND CreatedAt < @beforeUtc";

return _db.Database.ExecuteSqlRawAsync(sql, beforeUtc);
```

The vulnerability exists because:
1. `accountId` and `status` are interpolated into the SQL string using C# string interpolation (`$"...{variable}..."`)
2. This embeds the raw values directly into the query text
3. An attacker controlling these parameters can close the string quote and inject arbitrary SQL (e.g., `accountId = "' OR '1'='1"`)

## Fix
Replace the string interpolation with parameterized placeholders and use `ExecuteSqlInterpolatedAsync`, which safely handles parameter binding:

```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    var sql = $"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} " +
              $"AND Status = {status} AND CreatedAt < {beforeUtc}";

    return _db.Database.ExecuteSqlInterpolatedAsync(sql);
}
```

Alternatively, use `ExecuteSqlRawAsync` with explicit `SqlParameter` objects:

```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    var sql = "UPDATE Orders SET Archived = 1 WHERE AccountId = @accountId " +
              "AND Status = @status AND CreatedAt < @beforeUtc";

    return _db.Database.ExecuteSqlRawAsync(sql,
        new Microsoft.Data.SqlClient.SqlParameter("@accountId", accountId),
        new Microsoft.Data.SqlClient.SqlParameter("@status", status),
        new Microsoft.Data.SqlClient.SqlParameter("@beforeUtc", beforeUtc));
}
```

## Explanation
The first fix uses `ExecuteSqlInterpolatedAsync` with an interpolated string (`FormattableString`). EF Core detects this and automatically extracts the interpolated values as parameters, safely separating code from data. This is the idiomatic C# approach for parameterized queries in Entity Framework Core.

The second fix uses `ExecuteSqlRawAsync` with explicit `SqlParameter` objects. This is more verbose but achieves the same parameterization by passing each user-supplied value as a named parameter rather than embedding it in the string.

Both approaches prevent SQL injection by ensuring that `accountId` and `status` are passed as parameter values to the database, not as part of the SQL command text. The database driver then treats these values as data only, never as executable SQL.
