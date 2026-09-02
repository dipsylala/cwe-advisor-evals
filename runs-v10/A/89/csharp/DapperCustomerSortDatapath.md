## Verdict

Confirmed SQL injection vulnerability. Line 24 directly interpolates `options.Sort` into the SQL query without validation or parameterization.

## Source

The `options.Sort` value is taken from user input via `CustomerSearchOptions` and concatenated directly into the dynamic SQL query on line 24: `$"ORDER BY {options.Sort}"`. SQL parameter placeholders protect against injection for value parameters, but column names cannot be parameterized and must be validated against a whitelist before inclusion.

## Fix

Replace the dynamic SQL construction with a whitelist-validated approach:

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
    string accountId,
    CustomerSearchOptions options)
{
    // Whitelist allowed sort columns
    var allowedSortColumns = new[] { "Id", "Name", "Status" };
    if (!allowedSortColumns.Contains(options.Sort, StringComparer.OrdinalIgnoreCase))
    {
        throw new ArgumentException($"Invalid sort column: {options.Sort}", nameof(options.Sort));
    }

    var sql =
        "SELECT Id, Name, Status FROM Customers " +
        "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
        $"ORDER BY [{options.Sort}]";

    return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
}
```

## Explanation

SQL parameter placeholders (@AccountId, @Query) protect against injection for value-type parameters, but dynamic column names require a different approach. Validate `options.Sort` against a whitelist of known safe column names before inclusion in the query. If the value is not in the allowlist, reject it with an exception. Wrap the column identifier in square brackets to defend against reserved keywords and special characters, though the whitelist validation is the primary defense against injection.

