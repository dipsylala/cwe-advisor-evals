## Verdict

Confirmed. CWE-89 SQL Injection via the `sort` query parameter, which reaches the `ORDER BY` clause through raw string interpolation instead of a parameter binding.

## Source

`CustomerSearchController.Search` (`CustomerSearchController.cs:17`) reads the `sort` query-string value via `[FromQuery] string? sort`, defaulting to `"created_at"` when absent, and passes it unvalidated into `new CustomerSearchOptions(q ?? "", sort ?? "created_at")` (line 20).

Call chain:
1. `CustomerSearchController.Search` (line 20) - constructs `CustomerSearchOptions` from the raw query string, then calls `_service.SearchAsync(accountId, options)`.
2. `CustomerSearchService.SearchAsync` (`CustomerSearchService.cs:14-19`) - pure pass-through, forwards `options` unchanged to `_repository.SearchAsync(accountId, options)`.
3. `CustomerRepository.SearchAsync` (`CustomerRepository.cs:17-27`) - sink. Builds the SQL string with `$"ORDER BY {options.Sort}"` (line 24), leaving `options.Sort` as raw, unparameterized text concatenated into the query, then executes it with `_connection.QueryAsync<CustomerRow>(sql, ...)` (line 26, Dapper).

`AccountId` and `Query` are already correctly bound as `@AccountId`/`@Query` Dapper parameters - only the `ORDER BY` column is unsafe, because a column identifier cannot be passed as a bind parameter; it has to be validated before it reaches the SQL string.

## Fix

No library change needed - Dapper is already in use and already parameterizes `AccountId` and `Query` correctly. The fix is an allowlist that resolves the caller's `sort` value to a fixed, server-controlled column name before it is interpolated into the SQL text, per the C# CWE-89 guidance on dynamic identifiers.

Vulnerable code (`CustomerRepository.cs`):

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
    string accountId,
    CustomerSearchOptions options)
{
    var sql =
        "SELECT Id, Name, Status FROM Customers " +
        "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
        $"ORDER BY {options.Sort}"; // options.Sort is attacker-controlled and interpolated raw

    return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
}
```

Fixed code:

```csharp
using System.Collections.Generic;
using System.Data;
using Dapper;

namespace Cases.SqlInjection;

public sealed record CustomerRow(string Id, string Name, string Status);

public sealed class CustomerRepository
{
    // Server-controlled map: only these keys can ever reach the SQL text.
    private static readonly IReadOnlyDictionary<string, string> AllowedSortColumns =
        new Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase)
        {
            ["id"] = "Id",
            ["name"] = "Name",
            ["status"] = "Status",
            ["created_at"] = "CreatedAt",
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
        var sortColumn = AllowedSortColumns.TryGetValue(options.Sort, out var mapped)
            ? mapped
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

`options.Sort` cannot be bound as a Dapper parameter because it names a column, not a value, so the fix treats it as a key into a fixed, application-owned map rather than as text to validate and reuse. `AllowedSortColumns` enumerates the only column names the query is ever allowed to sort by; the raw request string is looked up in that map and the matched constant - never the caller's own string - is what gets interpolated into the SQL. Any value that is not a recognized key (including malicious payloads such as `Id; DROP TABLE Customers--`) falls through to `DefaultSortColumn` instead of reaching the query text, closing the injection point while leaving the already-correct `@AccountId` and `@Query` parameter bindings untouched.

## Behaviour changes

- An unrecognized or malicious `sort` value, which previously would have been interpolated as-is (either causing a SQL syntax error or executing injected SQL), now silently resolves to the default sort column (`CreatedAt`) instead of surfacing an error. Callers relying on an invalid `sort` value producing a visible failure will no longer see one.
- The set of valid `sort` values is now fixed to `id`, `name`, `status`, and `created_at` (case-insensitive). Any other column name that may have worked by accident before (e.g. an unfiltered but legitimate schema column) will now be silently redirected to the default instead of being honored - if additional sortable columns are needed, they must be added to `AllowedSortColumns` explicitly.
