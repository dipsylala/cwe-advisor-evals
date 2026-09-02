## Verdict

Exploitable (CWE-89, SQL Injection). Confidence: high.

## Source

`ArchiveController.Archive` (`ArchiveController.cs:17`) deserializes an `ArchiveRequest` from the
HTTP request body and passes `request.AccountId` / `request.Status` unmodified through
`ArchiveService.ArchiveAsync` (`ArchiveService.cs:12`) into
`OrderMaintenanceRepository.ArchiveOrdersAsync` (`OrderMaintenanceRepository.cs:14`). Both fields
are attacker-controlled, no validation or encoding occurs anywhere on the path, and both are
interpolated directly into a SQL string that reaches the sink at
`OrderMaintenanceRepository.cs:20`: `_db.Database.ExecuteSqlRawAsync(sql, beforeUtc)`. `beforeUtc`
is a `System.DateTime` and is not attacker-formattable in a way that breaks out of its `@beforeUtc`
placeholder, so it is not part of the injectable surface.

## Fix

Library: none needed - `Microsoft.EntityFrameworkCore` already provides the parameterizing API;
confirm the installed EF Core version against SCA/dependency-check tooling before merging.

Vulnerable code (`OrderMaintenanceRepository.cs:14-21`):

```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    var sql =
        // AccountId and Status are concatenated as raw string literals into the SQL text -
        // an attacker-controlled AccountId/Status can close the quote and inject SQL.
        $"UPDATE Orders SET Archived = 1 WHERE AccountId = '{accountId}' " +
        $"AND Status = '{status}' AND CreatedAt < @beforeUtc";

    return _db.Database.ExecuteSqlRawAsync(sql, beforeUtc);
}
```

Fixed code:

```csharp
public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
{
    System.FormattableString sql =
        $"UPDATE Orders SET Archived = 1 WHERE AccountId = {accountId} " +
        $"AND Status = {status} AND CreatedAt < {beforeUtc}";

    return _db.Database.ExecuteSqlInterpolatedAsync(sql);
}
```

Assumption: the project's EF Core major version could not be confirmed (no `.csproj` in the case
files), so `ExecuteSqlInterpolatedAsync` was used because it is the widely-compatible interpolated
API across EF Core versions. If the project targets EF Core 7.0 or later, the equivalent current
name is `ExecuteSqlAsync(FormattableString)`; behavior is identical.

## Explanation

The vulnerable code built the SQL text by string interpolation, embedding `accountId` and `status`
as quoted literals directly in the command, so a value such as `' OR '1'='1` closes the quote and
rewrites the `WHERE` clause (and a value containing `'; DROP TABLE Orders; --` chains a second
statement, subject to the driver's multi-statement behavior). The fix keeps the same interpolated
string shape but assigns it to `System.FormattableString` and passes it to
`Database.ExecuteSqlInterpolatedAsync`. EF Core compiles a `FormattableString` into a parameterized
command by converting each interpolation hole into a `DbParameter` bound by value rather than
substituting text into the SQL string - the literal quotes around `{accountId}` and `{status}` are
removed because they are no longer needed or valid once the values are bound as parameters instead
of literal text. `beforeUtc` moves from the previous named-placeholder/positional-argument pairing
to the same interpolation mechanism, with no change in how its value is bound.

## Behaviour changes

- Quoting removed around `{accountId}` and `{status}`: required, because these are now bound as
  typed parameter values rather than concatenated string literals; retaining the quotes would
  either produce invalid SQL or reintroduce a literal-text path.
- Sink call changed from `ExecuteSqlRawAsync(sql, beforeUtc)` to
  `ExecuteSqlInterpolatedAsync(sql)`: required to get EF Core's automatic parameterization of the
  interpolated values; the single `FormattableString` argument replaces the previous
  string-plus-positional-parameter signature.
- Return type, return value semantics (`Task<int>` rows-affected), and failure behavior (throws on
  SQL/database error) are unchanged - the sink contract identified in the trace is otherwise intact.
- No change to `ArchiveController.cs` or `ArchiveService.cs`; the source values continue to reach
  the repository unmodified, now made safe at the sink.
