## Verdict

SQL injection vulnerability confirmed. The `sort` query parameter is embedded unsafely into the SQL ORDER BY clause via string interpolation without parameterization or validation.

## Source

The `sort` query parameter originates from the HTTP GET request in `CustomerSearchController.Search()` (line 17) and flows through:
- `CustomerSearchController.Search()` → receives untrusted `sort` parameter from query string
- `CustomerSearchService.SearchAsync()` → passes through to repository (line 18)
- `CustomerRepository.SearchAsync()` → receives `options.Sort` and embeds it unsafely in the SQL query (line 24)

## Fix

The vulnerability lies in line 24 of `CustomerRepository.cs`, where the `sort` parameter is concatenated directly into the SQL query without validation. According to CWE-89 C# guidance, dynamic identifiers like column names in ORDER BY clauses cannot be safely parameterized—they must be validated against an allowlist of permitted values before being embedded in the query.

### File: CustomerRepository.cs

```csharp
using System.Data;
using Dapper;

namespace Cases.SqlInjection;

public sealed record CustomerRow(string Id, string Name, string Status);

public sealed class CustomerRepository
{
    private readonly IDbConnection _connection;
    private static readonly HashSet<string> AllowedSortColumns = new(StringComparer.OrdinalIgnoreCase)
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
        if (!AllowedSortColumns.Contains(options.Sort))
        {
            throw new ArgumentException("Invalid sort column specified.", nameof(options.Sort));
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

The fix introduces a static allowlist (`AllowedSortColumns`) containing the permitted sort column names. Before using the `options.Sort` value in the SQL query, the code now validates it against this allowlist using a case-insensitive string comparison. If the provided sort column is not in the allowlist, an `ArgumentException` is thrown, preventing the request from proceeding with an invalid or malicious value.

This approach follows the CWE-89 C# guidance principle: "Treat a dynamic identifier as a key into a server-side map of permitted names, not as input to validate and then use—the value reaching the query should be the map's, never the caller's." The validation is applied at the Repository layer where the SQL is constructed, closing the injection point. Only validated column names from the allowlist can reach the string interpolation in the ORDER BY clause.

The other parameters (`@AccountId` and `@Query`) remain safely parameterized via Dapper's parameter binding, which handles them as data, not SQL structure.

## Behaviour changes

**When valid sort columns are supplied (e.g., "Id", "Name", "Status", "created_at"):** The query executes as expected and returns sorted results. The allowlist uses case-insensitive comparison, so "id", "ID", "Id" all resolve to the same column.

**When an invalid or malicious sort column is supplied (e.g., "Id; DROP TABLE Customers", or "name' OR 1=1"):** The request fails immediately with an `ArgumentException` before the query is constructed. This prevents the SQL injection attack from reaching the database.

**No change to normal usage:** For legitimate sort parameters matching the allowlist, the functionality is identical to the original code. The SQL query structure, return type, and database result set are unchanged.
