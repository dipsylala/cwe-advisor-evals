## Verdict
CONFIRMED

## Source
Line 24 concatenates `options.Sort` directly into the SQL query using string interpolation: `$"ORDER BY {options.Sort}"`. The `Sort` parameter is attacker-controlled and not validated, allowing an attacker to inject arbitrary SQL.

## Fix
Validate the `Sort` parameter against a whitelist of allowed column names before using it in the SQL query. Reject any sort value not in the allowlist:

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
    string accountId,
    CustomerSearchOptions options)
{
    var validSort = options.Sort switch
    {
        "Id" or "Name" or "Status" => options.Sort,
        _ => throw new ArgumentException($"Invalid sort column: {options.Sort}", nameof(options.Sort))
    };
    
    var sql =
        "SELECT Id, Name, Status FROM Customers " +
        "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
        $"ORDER BY {validSort}";

    return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
}
```

## Explanation
SQL column names and ORDER BY clauses cannot be parameterized in SQL or Dapper; parameters bind only to values. The safe pattern is to validate the sort column against a hardcoded allowlist of permitted columns before concatenating it into the query. This prevents injection because only exact matches to known column names are accepted.
