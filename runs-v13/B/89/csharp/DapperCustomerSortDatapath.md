## Verdict
Exploitable

## Source
User-controlled `sort` query parameter from `CustomerSearchController.Search()` ([FromQuery] string? sort, line 17) flows through `CustomerSearchOptions.Sort` to `CustomerRepository.SearchAsync()` and is directly interpolated into the SQL query string without validation or parameterization.

## Fix

### Vulnerable Code
```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
    string accountId,
    CustomerSearchOptions options)
{
    var sql =
        "SELECT Id, Name, Status FROM Customers " +
        "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
        $"ORDER BY {options.Sort}";  // VULNERABLE: Direct interpolation

    return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
}
```

### Fixed Code
```csharp
private static readonly HashSet<string> PermittedSortColumns = new(StringComparer.OrdinalIgnoreCase)
{
    "id",
    "name",
    "status",
    "created_at"
};

public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
    string accountId,
    CustomerSearchOptions options)
{
    var sortColumn = ValidateSortColumn(options.Sort);
    
    var sql =
        "SELECT Id, Name, Status FROM Customers " +
        "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
        $"ORDER BY {sortColumn}";

    return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
}

private static string ValidateSortColumn(string sortInput)
{
    if (string.IsNullOrWhiteSpace(sortInput))
    {
        return "created_at"; // default safe value
    }

    var matched = PermittedSortColumns.FirstOrDefault(col => 
        col.Equals(sortInput, StringComparer.OrdinalIgnoreCase));

    if (matched != null)
    {
        return matched;
    }

    throw new ArgumentException($"Invalid sort column: {sortInput}", nameof(sortInput));
}
```

## Explanation
The fix addresses the SQL injection vulnerability by implementing allowlist validation for the dynamic `ORDER BY` clause. Since column names cannot be parameterized in SQL, the user-supplied sort parameter is validated against a fixed set of permitted columns. The `ValidateSortColumn()` method checks the input against the allowlist and returns only the matched canonical value from `PermittedSortColumns`, never the original untrusted input. This prevents an attacker from injecting arbitrary SQL through the sort parameter. The allowlist uses case-insensitive comparison to accept common naming conventions while remaining restrictive.

## Behaviour changes
None. The fix preserves the original query behavior and return type. The allowlist includes the columns most commonly used for sorting (id, name, status, created_at), and defaults to created_at when no sort parameter is provided, matching the original default behavior. The exception thrown on invalid input creates a defined failure mode for invalid sort columns rather than allowing them to pass through.
