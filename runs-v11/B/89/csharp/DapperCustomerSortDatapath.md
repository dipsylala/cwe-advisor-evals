## Verdict

Valid finding. SQL injection via unvalidated `ORDER BY` clause.

## Source

Query string parameter `sort` at CustomerSearchController line 17, flows through CustomerSearchOptions to CustomerRepository line 24 where it is interpolated into the SQL query string.

## Fix

Replace the vulnerable code in CustomerRepository.cs with allowlist validation:

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
    private static readonly HashSet<string> ValidSortColumns = new(StringComparer.OrdinalIgnoreCase)
    {
        "Id",
        "Name",
        "Status",
        "AccountId"
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
        if (!ValidSortColumns.Contains(options.Sort))
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

The vulnerability exists because `options.Sort` is user-controlled (originating from the HTTP query string parameter `sort`) and is interpolated directly into the SQL query at line 24. Dynamic identifiers like column names in ORDER BY clauses cannot be parameterized—SQL does not allow binding schema element names as parameters. Instead, the fix validates the input against a server-side allowlist of permitted sort columns and throws an ArgumentException if the value does not match. This ensures only known, safe column names can be used in the query, preventing SQL injection. The allowlist uses case-insensitive comparison to improve usability while maintaining security.

## Behaviour changes

- Requests with invalid sort column names now raise ArgumentException instead of executing a malformed query.
- Valid sort requests (using column names: Id, Name, Status, AccountId) behave identically to the original.
- Injection attempts (e.g., `sort=Name; DROP TABLE Customers; --`) are rejected with an exception instead of executing the injected SQL.
