## Verdict

Confirmed. `CustomerRepository.SearchAsync` builds its SQL by interpolating `options.Sort` directly into the `ORDER BY` clause. `AccountId` and `Query` are passed as Dapper parameters, but the sort value is concatenated as raw text, so any value that reaches `Sort` is executed as SQL syntax.

## Source

`CustomerSearchController.Search` reads the `sort` query-string parameter (`[FromQuery] string? sort`) with no validation, wraps it in a `CustomerSearchOptions`, and passes it through `CustomerSearchService.SearchAsync` unchanged into `CustomerRepository.SearchAsync`, where it is interpolated into the SQL string at `$"ORDER BY {options.Sort}"`. An attacker controls `sort` end to end (e.g. `?sort=1;DROP TABLE Customers;--` or a boolean/time-based subquery for blind extraction), giving classic ORDER-BY SQL injection.

## Fix

### File: CustomerRepository.cs
```csharp
using System.Collections.Generic;
using System.Data;
using Dapper;

namespace Cases.SqlInjection;

public sealed record CustomerRow(string Id, string Name, string Status);

public sealed class CustomerRepository
{
    private readonly IDbConnection _connection;

    private static readonly IReadOnlyDictionary<string, string> SortColumns =
        new Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase)
        {
            ["name"] = "Name ASC",
            ["name_desc"] = "Name DESC",
            ["status"] = "Status ASC",
            ["status_desc"] = "Status DESC",
            ["created_at"] = "CreatedAt ASC",
            ["created_at_desc"] = "CreatedAt DESC",
        };

    private const string DefaultSort = "Name ASC";

    public CustomerRepository(IDbConnection connection)
    {
        _connection = connection;
    }

    public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
        string accountId,
        CustomerSearchOptions options)
    {
        var orderBy = SortColumns.TryGetValue(options.Sort, out var mapped) ? mapped : DefaultSort;

        var sql =
            "SELECT Id, Name, Status FROM Customers " +
            "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
            $"ORDER BY {orderBy}";

        return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
    }
}
```

## Explanation

`ORDER BY` targets are identifiers, not data, so Dapper/ADO.NET parameters cannot bind them the way `@AccountId` and `@Query` are bound - a parameter placeholder there would be sent as a quoted string literal and would not sort anything. The fix keeps the interpolation but removes attacker control over its content: `options.Sort` is looked up in a fixed allowlist that maps known sort keys to hardcoded, safe `column direction` fragments (`Name ASC`, `Name DESC`, `Status ASC`, `Status DESC`, `CreatedAt ASC`, `CreatedAt DESC` - matching the API's existing `created_at` default). Only these hardcoded strings, never the raw request value, are concatenated into the SQL text, so no attacker-controlled substring can reach the query. Any unrecognized value (including malicious input) falls back to a safe default (`Name ASC`) rather than being rejected with an error that would leak validation details or require the caller to enumerate every legal value up front. `AccountId` and `Query` remain parameterized as before, so the `WHERE` clause is unaffected by this change.
