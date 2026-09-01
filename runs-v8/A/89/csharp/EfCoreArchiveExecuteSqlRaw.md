## Verdict
SQL Injection vulnerability via unparameterized string interpolation. User-supplied `accountId` and `status` parameters are interpolated directly into the SQL string without parameterization, allowing attackers to inject SQL code.

## Source
The vulnerability exists in `OrderMaintenanceRepository.ArchiveOrdersAsync()` at lines 16-18. The SQL query is constructed using string interpolation (`$"..."`), embedding `accountId` and `status` without parameterization:

```csharp
var sql =
    $"UPDATE Orders SET Archived = 1 WHERE AccountId = '{accountId}' " +
    $"AND Status = '{status}' AND CreatedAt < @beforeUtc";

return _db.Database.ExecuteSqlRawAsync(sql, beforeUtc);
```

An attacker controlling `accountId` or `status` can inject SQL commands; for example, `accountId = "' OR '1'='1` would modify the query logic.

## Fix
Replace `ExecuteSqlRawAsync` with `ExecuteSqlInterpolatedAsync`, which automatically parameterizes interpolated values:

```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    var sql = $"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} AND Status = {status} AND CreatedAt < {beforeUtc}";
    
    return _db.Database.ExecuteSqlInterpolatedAsync(sql);
}
```

Alternatively, use explicit parameterized queries with `ExecuteSqlRawAsync`:

```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    var sql = "UPDATE Orders SET Archived = 1 WHERE AccountId = @accountId AND Status = @status AND CreatedAt < @beforeUtc";
    
    return _db.Database.ExecuteSqlRawAsync(
        sql,
        new Microsoft.Data.SqlClient.SqlParameter("@accountId", accountId),
        new Microsoft.Data.SqlClient.SqlParameter("@status", status),
        new Microsoft.Data.SqlClient.SqlParameter("@beforeUtc", beforeUtc)
    );
}
```

## Explanation
Entity Framework Core's `ExecuteSqlInterpolatedAsync` method automatically parameterizes all values in the interpolated string, preventing SQL injection. This is safer than `ExecuteSqlRawAsync` with manual string concatenation. When using the parameterized `ExecuteSqlRawAsync` approach, all user-supplied values must be passed as separate parameters via the `SqlParameter` objects, ensuring the database engine treats them as data, not executable code. Both approaches ensure that special SQL characters in the values are safely escaped.
