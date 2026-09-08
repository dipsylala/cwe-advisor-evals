## Verdict
CONFIRMED: SQL injection via unvalidated ORDER BY clause in line 24.

## Source
`E:/Github/cwe-advisor/evals/cases/89/csharp/DapperCustomerSortDatapath/CustomerRepository.cs` at line 24:
```csharp
$"ORDER BY {options.Sort}"
```

The `Sort` parameter from `CustomerSearchOptions` is passed directly from user-controlled query parameters (via `CustomerSearchController`) and interpolated unsanitized into the SQL query. An attacker can inject arbitrary SQL through the `sort` query parameter.

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

    public CustomerRepository(IDbConnection connection)
    {
        _connection = connection;
    }

    public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
        string accountId,
        CustomerSearchOptions options)
    {
        // Allowlist of valid sort columns to prevent SQL injection
        var validSortColumns = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Id", "Name", "Status", "created_at"
        };

        // Reject sort values not in the allowlist
        if (string.IsNullOrEmpty(options.Sort) || !validSortColumns.Contains(options.Sort))
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
The vulnerability stems from string interpolation of the untrusted `Sort` parameter into a SQL query. ORDER BY clauses cannot be parameterized in standard SQL, so the fix validates the sort value against an explicit allowlist of safe column names before interpolating it.

The allowlist includes: `Id`, `Name`, `Status` (selected columns), and `created_at` (the default sort column used in the controller). Any value outside this set is rejected with an `ArgumentException`.

This approach ensures that only known, safe column identifiers can be used for sorting, eliminating the injection vector while maintaining the intended functionality.
