## Verdict

Exploitable. CWE-89 (SQL Injection), high confidence.

## Source

`CustomerSearchController.Search` (`CustomerSearchController.cs:17-20`) reads the `sort` query-string parameter directly from the HTTP request (`[FromQuery] string? sort`), defaults it to `"created_at"` only when absent, and passes it unvalidated into a new `CustomerSearchOptions(q ?? "", sort ?? "created_at")`. `CustomerSearchService.SearchAsync` (`CustomerSearchService.cs:14-19`) forwards the options object unchanged to the repository. `CustomerRepository.SearchAsync` (`CustomerRepository.cs:17-27`) interpolates `options.Sort` directly into the SQL text at line 24 (`$"ORDER BY {options.Sort}"`), and that string is executed at the sink, `_connection.QueryAsync<CustomerRow>(sql, ...)` on line 26. `AccountId` and `Query` are correctly bound as Dapper parameters, but `Sort` never passes through parameter binding - it becomes part of the SQL command text itself. An attacker controls `sort` fully (e.g. `?sort=Id;--` or a boolean/UNION-based payload appended after a valid-looking column name) and it reaches `QueryAsync` with no intervening validation, allowlist, or escaping.

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
    private static readonly IReadOnlyDictionary<string, string> AllowedSortColumns =
        new Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase)
        {
            ["created_at"] = "CreatedAt",
            ["name"] = "Name",
            ["status"] = "Status",
        };

    private const string DefaultSortColumn = "CreatedAt";

    private readonly IDbConnection _connection;

    public CustomerRepository(IDbConnection connection)
    {
        _connection = connection;
    }

    public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
        string accountId,
        CustomerSearchOptions options)
    {
        var sortColumn = AllowedSortColumns.TryGetValue(options.Sort, out var mappedColumn)
            ? mappedColumn
            : DefaultSortColumn;

        var sql =
            "SELECT Id, Name, Status FROM Customers " +
            "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
            $"ORDER BY {sortColumn}";

        return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
    }
}
```

## Explanation

`AccountId` and `Query` were already safe - Dapper binds them as real `SqlParameter`/`DbParameter` values, so they cannot alter query structure. `Sort` was the exception: it fills the `ORDER BY` position, and no database placeholder can bind a column identifier, only a value, so parameterizing it the same way was never an option. The fix follows the CWE-89 C# guidance's identifier rule - resolve the caller-supplied sort key against a fixed, server-side allowlist (`AllowedSortColumns`) and use the allowlist's own mapped column name, never the raw request string, at the interpolation point. `TryGetValue` performs the lookup; on a match, `mappedColumn` is one of three hardcoded literals (`"CreatedAt"`, `"Name"`, `"Status"`) the application controls, so the resulting SQL text is fixed at compile time regardless of what the caller sent. Any value not in the map - including an injection payload - falls back to the same hardcoded default the endpoint already used when `sort` was absent, so no attacker-influenced text ever reaches the SQL string. The bound parameters for `AccountId` and `Query` are unchanged.

## Behaviour changes

- Sort keys outside `{created_at, name, status}` now silently fall back to `CreatedAt` ordering instead of being concatenated into the query. Previously an unrecognized value produced either a SQL syntax error (fails closed, but as a 500) or, if it happened to be valid SQL, silently altered query behavior; now it produces a normal result set sorted by the default column instead of an error. This is a deliberate consequence of closing the injection - a dynamic `ORDER BY` cannot be validated field-by-field and then still concatenated safely, so any value not proven safe must be replaced rather than passed through.
- Sort-key matching is now case-insensitive (`OrdinalIgnoreCase`), whereas the original code passed the raw string through unchanged, so casing only mattered if it happened to match a real column name in the underlying SQL. This has no security effect and only affects which literal strings resolve to which column.
- The allowlist assumes `name`, `status`, and `created_at` (matching `CustomerRow`'s selected columns and the controller's existing default) are the full set of supported sort keys, and that the underlying `Customers` table has a `CreatedAt` column, consistent with the existing default value of `"created_at"` used before this fix. It also assumes only ascending order was previously reachable through legitimate use - the original code had no separate direction parameter, so a caller could only get a different order by supplying a different full `ORDER BY` expression (e.g. `"Name DESC"`), which this fix no longer permits since only bare column identifiers are in the allowlist. If descending order or additional sort fields are a required feature, extend `AllowedSortColumns` with explicit entries (e.g. `["name_desc"] = "Name DESC"`) rather than accepting free-form direction text.

## Verification

Compiled: copied the three files (fixed `CustomerRepository.cs` plus the unchanged `CustomerSearchService.cs` and `CustomerSearchController.cs`) into a scratch `net8.0` class-library project referencing the `Dapper` NuGet package (matching the sink's namespace) and ran `dotnet build`. Result: build succeeded, 0 warnings, 0 errors. All new symbols used in the fix - `System.Collections.Generic.Dictionary<TKey,TValue>`, `IReadOnlyDictionary<TKey,TValue>`, `System.StringComparer.OrdinalIgnoreCase`, and `IReadOnlyDictionary<TKey,TValue>.TryGetValue` - are BCL types/members (`System.Collections.Generic`, `System` namespaces), confirmed by the successful compile rather than by recall.
