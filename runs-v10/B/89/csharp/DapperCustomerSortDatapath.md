## Verdict

Confirmed exploitable SQL injection via ORDER BY clause. The `Sort` parameter from `CustomerSearchController.Search()` flows through `CustomerSearchService` to `CustomerRepository.SearchAsync()` where it is directly interpolated into the SQL query without validation or parameterization. Dapper executes the unsanitized query, allowing an attacker to inject arbitrary SQL.

## Source

**Data flow:**
1. `CustomerSearchController.Search([FromQuery] string? sort)` receives untrusted query string parameter
2. Defaults to `"created_at"` and wraps in `CustomerSearchOptions(q ?? "", sort ?? "created_at")`
3. `CustomerSearchService.SearchAsync()` forwards unchanged to `CustomerRepository.SearchAsync()`
4. `CustomerRepository.SearchAsync()` interpolates `options.Sort` directly into SQL string at line 24:
   ```csharp
   $"ORDER BY {options.Sort}"
   ```
5. SQL is executed by Dapper at line 26: `_connection.QueryAsync<CustomerRow>(sql, ...)`

**Exploit example:** A request with `sort=created_at; DROP TABLE Customers; --` executes two statements instead of one.

## Fix

Replace the `CustomerRepository.SearchAsync()` method to validate the sort column against an allowlist before interpolating it into the query. The fixed method must:

1. Validate the untrusted `options.Sort` value against a set of permitted column names
2. Use the validated constant value from the allowlist, never the original input
3. Keep parameterized query parameters for row-level data

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
    string accountId,
    CustomerSearchOptions options)
{
    // Allowlist of permitted column names for ORDER BY
    var permittedColumns = new Dictionary<string, string>
    {
        { "created_at", "CreatedAt" },
        { "name", "Name" },
        { "status", "Status" },
        { "id", "Id" }
    };

    // Validate and select the safe column name
    if (!permittedColumns.TryGetValue(options.Sort.ToLower(), out var sortColumn))
    {
        // Default to a safe column if the provided value is not in the allowlist
        sortColumn = "CreatedAt";
    }

    // Construct the SQL with the validated identifier, not the user input
    var sql =
        "SELECT Id, Name, Status FROM Customers " +
        "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
        $"ORDER BY {sortColumn}";

    return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
}
```

## Explanation

The ORDER BY clause accepts column identifiers, which cannot be parameterized in SQL. The fix establishes a server-side allowlist of permitted column names and validates the untrusted input against it. Only after a successful match does the query use the matched constant value from the allowlist—never the original user input. This prevents an attacker from injecting arbitrary SQL while preserving the intended sorting functionality.

The parameterized bindings for `@AccountId` and `@Query` remain intact, providing layered defense for row-level data. The allowlist is application-controlled and closes the injection vector entirely, since no value can reach the SQL unless it is explicitly permitted.

## Behaviour changes

- **Column resolution:** Sort requests are now restricted to permitted columns: `created_at`, `name`, `status`, `id` (case-insensitive). Any other value defaults to `created_at` instead of being interpolated into the query.
- **Query construction:** The SQL query now interpolates a validated constant identifier instead of the untrusted input.
- **No functional regression:** Legitimate sort requests for permitted columns continue to work as before, with identical result ordering and performance.
