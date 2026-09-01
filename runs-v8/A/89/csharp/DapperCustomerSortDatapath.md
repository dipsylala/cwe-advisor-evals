## Verdict
SQL Injection vulnerability confirmed. Line 24 uses string interpolation to include `options.Sort` directly in the SQL ORDER BY clause without parameterization or validation, allowing arbitrary SQL injection.

## Source
Line 24: `$"ORDER BY {options.Sort}"`

The `Sort` parameter from `options` is directly interpolated into the SQL query string. Column names and ORDER BY clauses cannot be parameterized in SQL, so any untrusted value is injected directly into the query.

## Fix
Validate `options.Sort` against a whitelist of allowed column names before using it in the query:

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
    string accountId,
    CustomerSearchOptions options)
{
    var allowedSortColumns = new[] { "Id", "Name", "Status" };
    if (!allowedSortColumns.Contains(options.Sort, StringComparer.OrdinalIgnoreCase))
    {
        throw new ArgumentException($"Invalid sort column: {options.Sort}", nameof(options.Sort));
    }

    var sql =
        "SELECT Id, Name, Status FROM Customers " +
        "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
        $"ORDER BY {options.Sort}";

    return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
}
```

## Explanation
Column names and ORDER BY expressions cannot be parameterized in SQL. The whitelist approach restricts `Sort` to known, safe column names before interpolation. If an untrusted sort value reaches the method, it raises an exception before entering the query, preventing injection. The whitelist ensures only valid schema elements are included in the final SQL string.
