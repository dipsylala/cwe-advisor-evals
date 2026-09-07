## Verdict

SQL injection vulnerability confirmed. The `options.Sort` parameter is directly interpolated into the SQL query string without validation, allowing attackers to inject arbitrary SQL commands via the sort query parameter.

## Source

- **Entry point**: `CustomerSearchController.Search()` receives untrusted `sort` query parameter from HTTP request (line 17)
- **Propagation**: Parameter passed through `CustomerSearchService.SearchAsync()` to `CustomerRepository.SearchAsync()` as `options.Sort`
- **Sink**: Direct string interpolation on line 24: `$"ORDER BY {options.Sort}"` embeds untrusted value into SQL query passed to `_connection.QueryAsync<CustomerRow>()`

## Fix

### File: CustomerRepository.cs

```csharp
using System;
using System.Collections.Generic;
using System.Data;
using Dapper;

namespace Cases.SqlInjection;

public sealed record CustomerRow(string Id, string Name, string Status);

public sealed class CustomerRepository
{
    private readonly IDbConnection _connection;
    
    // Allowlist of permitted sort columns
    private static readonly HashSet<string> PermittedSortColumns = new(StringComparer.OrdinalIgnoreCase)
    {
        "Id",
        "Name", 
        "Status",
        "created_at"
    };

    public CustomerRepository(IDbConnection connection)
    {
        _connection = connection;
    }

    public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
        string accountId,
        CustomerSearchOptions options)
    {
        // Validate sort column against allowlist
        if (!PermittedSortColumns.Contains(options.Sort))
        {
            throw new ArgumentException($"Invalid sort column: {options.Sort}", nameof(options.Sort));
        }

        var sql =
            "SELECT Id, Name, Status FROM Customers " +
            "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
            $"ORDER BY {options.Sort}";

        return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
    }
}
```

## Explanation

Column names and `ORDER BY` directives cannot be parameterized in SQL—they are part of query structure, not data. The fix uses an allowlist of permitted column names known to be safe (`Id`, `Name`, `Status`, and `created_at`). The validation on line 33 checks that `options.Sort` matches one of these allowed values before it reaches the query on line 40. If an attacker supplies a value not in the allowlist (e.g., `Id; DROP TABLE Customers; --`), an `ArgumentException` is thrown, blocking execution. The rest of the query remains parameterized: `@AccountId` and `@Query` are still passed as separate parameters to `QueryAsync`, preventing injection through those fields.

## Behaviour changes

- **Request validation**: Invalid sort column values now raise `ArgumentException` instead of being silently embedded in the query. Requests with sort parameters outside the allowlist will fail with HTTP 500 (unless caught and handled by caller).
- **Default handling**: The default sort value "created_at" (provided by `CustomerSearchController` on line 20) remains in the allowlist and functions as before.
- **Functional scope**: Sort ordering is restricted to the four permitted columns, which matches the columns available in the `SELECT` clause and the expected business logic. Requests for undefined columns are rejected.
