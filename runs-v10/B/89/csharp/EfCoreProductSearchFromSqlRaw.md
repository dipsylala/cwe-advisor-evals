## Verdict

Real vulnerability. SQL injection via unsanitized user input in `FromSqlRaw()` call.

## Source

The `SearchAsync` method receives untrusted parameters `tenantId` and `term` from the caller. These values originate from user input (HTTP request parameters, external data sources, etc.).

## Fix

Replace the concatenated SQL string with `FromSqlInterpolated` to parameterize the user-supplied values:

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.List<Product>> SearchAsync(string tenantId, string term)
{
    return _db.Products.FromSqlInterpolated($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {$"%{term}%"}").ToListAsync();
}
```

Alternatively, if using EF Core 7.0+, use `FromSql` with interpolated strings:

```csharp
public System.Threading.Tasks.Task<System.Collections.Generic.List<Product>> SearchAsync(string tenantId, string term)
{
    return _db.Products.FromSql($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {$"%{term}%"}").ToListAsync();
}
```

## Explanation

The vulnerability exists because user-supplied `tenantId` and `term` are directly interpolated into the SQL string using `$""` syntax and passed to `FromSqlRaw()`, which executes the raw concatenated SQL without treating the values as parameters. An attacker can inject SQL metacharacters to manipulate the query logic—for example, passing `term = "x' OR '1'='1"` modifies the query to return unauthorized records.

`FromSqlInterpolated()` (or `FromSql()` in EF Core 7.0+) wraps each interpolated value in a `DbParameter` automatically, ensuring that user input is treated as data, not as executable SQL code. The database receives the SQL structure separately from the parameter values, preventing injection. This is the primary defence for EF Core and preserves the existing return type and async behavior.

## Behaviour changes

None. The query returns the same result set for valid inputs. Malicious payloads that previously succeeded in altering query logic are now neutralized because the string content is passed as a parameter value, not part of the query text.
