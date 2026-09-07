## Verdict

Exploitable. The `ORDER BY` clause on line 24 incorporates untrusted user input (`options.Sort`) via string interpolation without validation or allowlisting, enabling SQL injection.

## Source

HTTP request query parameter `sort` in `CustomerSearchController.Search()` (line 17), passed through `CustomerSearchService.SearchAsync()` (line 18) to `CustomerRepository.SearchAsync()` as the `Sort` property of `CustomerSearchOptions` (line 20).

## Fix

**Vulnerable code (CustomerRepository.cs, lines 21–26):**

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
    string accountId,
    CustomerSearchOptions options)
{
    var sql =
        "SELECT Id, Name, Status FROM Customers " +
        "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
        $"ORDER BY {options.Sort}";

    return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
}
```

**Fixed code:**

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
    string accountId,
    CustomerSearchOptions options)
{
    // Map user-supplied sort values to trusted database column names
    var sortColumnMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        { "id", "Id" },
        { "name", "Name" },
        { "status", "Status" },
        { "created_at", "CreatedAt" }
    };
    
    // Default to a safe column if the requested sort is not in the allowlist
    var sortColumn = "CreatedAt";
    if (!string.IsNullOrEmpty(options.Sort) && sortColumnMap.TryGetValue(options.Sort, out var mappedColumn))
    {
        sortColumn = mappedColumn;
    }
    
    var sql =
        "SELECT Id, Name, Status FROM Customers " +
        "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
        $"ORDER BY {sortColumn}";

    return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
}
```

## Explanation

Dynamic SQL identifiers such as column names in `ORDER BY` cannot be parameterized, because the database driver treats parameters as values only. The fix uses an allowlist (`sortColumnMap`) that maps user-friendly sort values (e.g., `"created_at"`) to trusted database column names (e.g., `"CreatedAt"`). The user input is validated against this map using case-insensitive comparison. If a match is found, the canonical column name from the map is used; if not, a safe default (`"CreatedAt"`) is applied. This ensures that only the application-controlled column names can reach the SQL query, eliminating the injection point while preserving the dynamic sorting functionality.

## Behaviour changes

None. The fix preserves the original method signature, return type, and functional contract. The `QueryAsync` call receives the same parameters and returns the same result set. The allowlist validates and maps the sort value before use, so legitimate sort requests proceed normally while malicious payloads are rejected in favour of the safe default.
