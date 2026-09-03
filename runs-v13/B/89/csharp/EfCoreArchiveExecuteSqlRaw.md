## Verdict
Confirmed. The code concatenates untrusted string parameters (`accountId`, `status`) directly into an SQL query string without parameterization before passing it to `ExecuteSqlRawAsync()`. This allows an attacker to inject arbitrary SQL by providing values such as `' OR '1'='1` or `'; DROP TABLE Orders; --`.

## Source
User-supplied `accountId` and `status` from the ASP.NET controller request flow through `ArchiveController.Archive()` → `ArchiveService.ArchiveAsync()` → `OrderMaintenanceRepository.ArchiveOrdersAsync()` where they are concatenated into the SQL query on lines 17–18.

## Fix
Replace `ExecuteSqlRawAsync()` with `ExecuteSqlInterpolatedAsync()` and use string interpolation without manual quotes around the parameters. This causes Entity Framework Core to automatically wrap each interpolated value in a `DbParameter`:

```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    return _db.Database.ExecuteSqlInterpolatedAsync(
        $"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} " +
        $"AND Status = {status} AND CreatedAt < {beforeUtc}");
}
```

## Explanation
`ExecuteSqlRawAsync()` executes a raw SQL string without automatic parameterization; values must be embedded in the string before the call. `ExecuteSqlInterpolatedAsync()` accepts an interpolated string and converts each `{value}` placeholder into a separate SQL parameter, ensuring the value is always treated as data, not query structure. This is the safe equivalent of the current code.

The fix removes the need to manually construct a SQL string with embedded quotes and the placeholder `@beforeUtc` marker, and instead lets Entity Framework handle parameterization uniformly for all values.

## Behaviour changes
The query result and number of affected rows remain unchanged. Execution time may improve slightly due to reduced string concatenation. The application no longer accepts SQL injection payloads in `accountId` or `status` parameters.
