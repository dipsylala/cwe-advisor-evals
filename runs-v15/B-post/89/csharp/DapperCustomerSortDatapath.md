## Verdict
Exploitable. The `Sort` parameter from the HTTP query string is passed directly into the SQL ORDER BY clause without validation or parameterization, allowing SQL injection.

## Source
HTTP query parameter `sort` in `CustomerSearchController.Search()` (line 17), passed through `CustomerSearchService.SearchAsync()` to `CustomerRepository.SearchAsync()` in the `CustomerSearchOptions.Sort` field.

## Fix

**Vulnerable code (line 22-26):**
```csharp
var sql =
    "SELECT Id, Name, Status FROM Customers " +
    "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
    $"ORDER BY {options.Sort}";

return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
```

**Fixed code:**
```csharp
// Whitelist of permitted sort columns
var permittedSortColumns = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
{
    { "id", "Id" },
    { "name", "Name" },
    { "status", "Status" },
    { "created_at", "created_at" }
};

// Validate and retrieve the canonical sort column name
if (!permittedSortColumns.TryGetValue(options.Sort, out var safeSortColumn))
{
    throw new ArgumentException($"Invalid sort column: {options.Sort}", nameof(options.Sort));
}

var sql =
    "SELECT Id, Name, Status FROM Customers " +
    "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
    $"ORDER BY {safeSortColumn}";

return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
```

## Explanation
SQL column names and ORDER BY directions cannot be parameterized - no SQL database permits binding identifiers as parameters. The fix applies an allowlist of canonical column names, validates the user-supplied sort parameter against it, and uses only the validated canonical value in the query. An attacker cannot inject SQL through the sort parameter because the query either uses a whitelisted value or throws an exception before execution. The `StringComparer.OrdinalIgnoreCase` allows case-insensitive input (`"ID"`, `"Id"`, `"id"`) while always using the canonical schema-correct casing (`"Id"`). All user-supplied row-value parameters (`@AccountId`, `@Query`) remain parameterized.

## Behaviour changes
- Invalid sort values now throw `ArgumentException` before query execution (previously would execute unsafe SQL). This is the intended security-critical change.
- The dictionary lookup adds minimal runtime overhead (negligible for query execution).
- Existing callers passing valid sort values ("id", "name", "status", "created_at") see no functional change beyond security hardening.
