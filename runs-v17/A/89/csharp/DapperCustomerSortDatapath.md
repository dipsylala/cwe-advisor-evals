## Verdict
CONFIRMED. SQL injection vulnerability via unsanitized `Sort` parameter on line 24.

## Source
The vulnerability exists in `CustomerRepository.cs`, line 24:
```csharp
$"ORDER BY {options.Sort}"
```

The `Sort` value originates from user input via the HTTP query parameter `sort` in `CustomerSearchController.cs` (line 20) and is passed through `CustomerSearchService` to the repository without validation. Direct string interpolation into SQL allows an attacker to inject arbitrary SQL code.

## Fix
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
        // Validate sort column against whitelist to prevent SQL injection
        if (!AllowedSortColumns.Contains(options.Sort))
        {
            throw new ArgumentException($"Invalid sort column: {options.Sort}", nameof(options));
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
SQL injection via ORDER BY clauses cannot be prevented with parameterized queries, as SQL databases do not support column names as parameters. The fix validates the `Sort` input against a whitelist of known safe column names before interpolating it into the SQL query.

The whitelist includes columns that can be returned and sorted by the query (`Id`, `Name`, `Status`) plus the default value used in the controller (`created_at`). Using `StringComparer.OrdinalIgnoreCase` allows case-insensitive matching while safely handling the input.

If an invalid sort column is provided, an `ArgumentException` is thrown, causing the request to fail explicitly rather than executing potentially malicious SQL.
