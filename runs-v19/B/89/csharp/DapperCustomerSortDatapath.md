## Verdict
EXPLOITABLE SQL INJECTION via untrusted sort parameter directly interpolated into ORDER BY clause.

## Source
HTTP query parameter `sort` in CustomerSearchController.cs line 17 (`[FromQuery] string? sort`), passed through CustomerSearchService to CustomerRepository with no validation.

## Fix
The sort parameter is a dynamic identifier that cannot be parameterized. Validate it against a fixed allowlist of permitted column names and use only the canonical value from the allowlist in the SQL query.

### File: CustomerRepository.cs

```csharp
using System.Data;
using Dapper;

namespace Cases.SqlInjection;

public sealed record CustomerRow(string Id, string Name, string Status);

public sealed class CustomerRepository
{
    private readonly IDbConnection _connection;
    
    // Allowlist of permitted sort columns mapped to safe identifiers
    private static readonly Dictionary<string, string> AllowedSortColumns = new(StringComparer.OrdinalIgnoreCase)
    {
        { "id", "Id" },
        { "name", "Name" },
        { "status", "Status" },
        { "created_at", "CreatedAt" }
    };

    public CustomerRepository(IDbConnection connection)
    {
        _connection = connection;
    }

    public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
        string accountId,
        CustomerSearchOptions options)
    {
        // Validate sort parameter against allowlist; use default if not found
        var sortColumn = "Id";
        if (!string.IsNullOrEmpty(options.Sort) && 
            AllowedSortColumns.TryGetValue(options.Sort, out var validatedSort))
        {
            sortColumn = validatedSort;
        }

        var sql =
            "SELECT Id, Name, Status FROM Customers " +
            "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
            $"ORDER BY {sortColumn}";

        return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
    }
}
```

## Explanation
The original code interpolated the untrusted `options.Sort` parameter directly into the SQL query using string interpolation (`$"ORDER BY {options.Sort}"`). This bypasses parameterization and allows SQL injection attacks such as `sort=Id; DROP TABLE Customers;--`.

The fix defines a static allowlist dictionary that maps user-provided sort values (case-insensitive) to safe, application-controlled column names. The `SearchAsync` method now validates the sort parameter against this allowlist and uses only the validated canonical value (`sortColumn`) in the SQL query. If the parameter is missing or not in the allowlist, it defaults to "Id".

This approach:
1. **Closes the injection vector** – only allowlisted identifiers can reach the query
2. **Preserves the sort functionality** – legitimate sort requests via permitted columns still work
3. **Matches the existing parameterization pattern** – `@AccountId` and `@Query` remain parameterized; only the column identifier (which cannot be parameterized) is now safely controlled
4. **Maintains backward compatibility** – the public API signature is unchanged

## Behaviour changes
- Sort values not in the allowlist (e.g., `sort=invalid_column`) now default to sorting by `Id` instead of being directly interpolated into the query
- The sort parameter lookup is case-insensitive due to `StringComparer.OrdinalIgnoreCase`
- No other query logic or return behavior is affected
