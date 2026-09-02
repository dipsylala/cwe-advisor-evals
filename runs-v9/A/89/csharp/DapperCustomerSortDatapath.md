## Verdict

Confirmed. `CustomerRepository.SearchAsync` builds its SQL string with `$"ORDER BY {options.Sort}"`, splicing `options.Sort` directly into the command text instead of passing it as a parameter. `options.Sort` originates from the `sort` query-string parameter on `CustomerSearchController.Search` (`[FromQuery] string? sort`), defaults to `"created_at"` only when absent, and is passed unmodified through `CustomerSearchService.SearchAsync` into the repository with no allowlist, validation, or escaping anywhere on the path. A request such as `GET /api/customers?sort=1;DROP TABLE Customers--` reaches the database verbatim in the `ORDER BY` clause.

## Source

`sort` query-string parameter, `CustomerSearchController.Search` (`CustomerSearchController.cs`, line 17) -> `CustomerSearchOptions.Sort` -> `CustomerSearchService.SearchAsync` (`CustomerSearchService.cs`, line 18, pass-through) -> `CustomerRepository.SearchAsync` (`CustomerRepository.cs`, line 24), where it is interpolated into the SQL string executed by `_connection.QueryAsync` at line 26.

## Fix

```csharp
using System.Data;
using Dapper;

namespace Cases.SqlInjection;

public sealed record CustomerRow(string Id, string Name, string Status);

public sealed class CustomerRepository
{
    private readonly IDbConnection _connection;

    // Allowlist mapping caller-facing sort keys to literal, trusted SQL fragments.
    // Only values on this list can ever reach the ORDER BY clause.
    private static readonly System.Collections.Generic.Dictionary<string, string> AllowedSorts =
        new(System.StringComparer.OrdinalIgnoreCase)
        {
            ["created_at"] = "CreatedAt",
            ["created_at_desc"] = "CreatedAt DESC",
            ["name"] = "Name",
            ["name_desc"] = "Name DESC",
            ["status"] = "Status",
        };

    private const string DefaultSort = "CreatedAt";

    public CustomerRepository(IDbConnection connection)
    {
        _connection = connection;
    }

    public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
        string accountId,
        CustomerSearchOptions options)
    {
        var orderBy = AllowedSorts.TryGetValue(options.Sort, out var mapped)
            ? mapped
            : DefaultSort;

        var sql =
            "SELECT Id, Name, Status FROM Customers " +
            "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
            $"ORDER BY {orderBy}";

        return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
    }
}
```

## Explanation

`AccountId` and `Query` are already safe: they are passed as Dapper parameters (`@AccountId`, `@Query`), which the ADO.NET provider binds separately from the SQL text and cannot be broken out of. `options.Sort` is different only because it names a column/direction rather than a value, and SQL has no parameter placeholder for identifiers - a bound parameter is always treated as a literal value, so `@Sort` could not be used to parameterize `ORDER BY` even if attempted. That is why the code fell back to string interpolation, and why the fix cannot be "just parameterize it."

The correct primary defense for a caller-controlled identifier is a fixed allowlist: define the finite set of sort keys the API is meant to support, map each one to its literal, developer-authored SQL fragment, and look up the caller's value against that map. Any value that isn't an exact allowlist key - including an empty string, a malformed key, or an injection payload - falls through to a safe, hardcoded default (`CreatedAt`) rather than being concatenated into the query. Because every string that can reach the SQL text now comes from the fixed set of values on the right-hand side of the dictionary (never from `options.Sort` itself), the attacker-controlled input can only ever select among predetermined, safe fragments and never contributes characters to the command text. This closes the injection while preserving the sorting behavior the endpoint is meant to offer; if additional sortable columns are needed, they should be added to `AllowedSorts` explicitly rather than the check being relaxed to a denylist or a character-filtering approach, which are both bypassable against SQL syntax as varied as `ORDER BY`.
