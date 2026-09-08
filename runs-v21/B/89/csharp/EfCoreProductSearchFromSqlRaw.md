## Verdict

SQL injection vulnerability confirmed on line 17. The `SearchAsync` method constructs an SQL query by directly interpolating untrusted parameters (`tenantId` and `term`) into a query string, then passes it to `FromSqlRaw()`. This allows an attacker to inject arbitrary SQL. The fix is to use `FromSqlInterpolated()`, which automatically parameterizes interpolated values.

## Source

**Entry point**: HTTP GET query parameter `q` in `ProductSearchController.Search()`

**Data path**:
1. `q` parameter received from HTTP request (untrusted)
2. Passed as `term` argument to `ProductSearchRepository.SearchAsync(tenantId, q ?? "")`
3. `tenantId` extracted from JWT claim (controlled by attacker's token)
4. Both values interpolated directly into SQL string on line 17: `$"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'"`
5. Unsanitized SQL passed to `FromSqlRaw(sql)` on line 18

**Exploitability**: An attacker can inject SQL through either the `term` or `tenantId` parameter. Example payload: `term = "' OR '1'='1"` produces `LIKE '%' OR '1'='1%'`, bypassing the name filter.

## Fix

### File: ProductSearchRepository.cs

```csharp
using Microsoft.EntityFrameworkCore;

namespace Cases.SqlInjection;

public sealed class ProductSearchRepository
{
    private readonly CatalogDbContext _db;

    public ProductSearchRepository(CatalogDbContext db)
    {
        _db = db;
    }

    public System.Threading.Tasks.Task<System.Collections.Generic.List<Product>> SearchAsync(string tenantId, string term)
    {
        var pattern = $"%{term}%";
        return _db.Products.FromSqlInterpolated($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {pattern}").ToListAsync();
    }
}

public sealed class CatalogDbContext : DbContext
{
    public DbSet<Product> Products => Set<Product>();
}

public sealed class Product
{
    public string Id { get; set; } = "";
    public string TenantId { get; set; } = "";
    public string Name { get; set; } = "";
}
```

## Explanation

The fix replaces `FromSqlRaw()` with `FromSqlInterpolated()`, which is Entity Framework Core's parameterized query method. When `FromSqlInterpolated()` processes an interpolated string (`$"..."`), it wraps each interpolated value in a `DbParameter`, ensuring they are always treated as data, never as executable SQL syntax. 

The line `var pattern = $"%{term}%";` constructs the search pattern with the wildcard delimiters, and this entire pattern (including the term) is then passed as a single parameterized value to the SQL query. Both `tenantId` and `pattern` are now passed to the database as parameters, preventing SQL injection even if they contain single quotes, SQL keywords, or other malicious content.

## Behaviour changes

**Preservation of functionality**: The query logic is unchanged - it still filters by TenantId and searches for the term anywhere in the Name field using LIKE. The result type, return value, and async behavior all remain identical.

**Parameterization**: Values are now sent to the database engine as typed parameters rather than embedded in the SQL string. This has no visible impact on the application but eliminates the injection vector.

**No other changes**: The method signature, exception handling, and interaction with the DbContext are unchanged.
