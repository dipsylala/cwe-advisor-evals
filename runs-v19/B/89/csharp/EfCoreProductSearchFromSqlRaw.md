## Verdict

The finding is confirmed as exploitable. The code directly concatenates untrusted parameters into a SQL query via string interpolation before passing it to `FromSqlRaw()`, creating a SQL injection vulnerability.

## Source

**Call chain:**
1. User provides untrusted query parameter `q` via HTTP GET request to `ProductSearchController.Search()`
2. `tenantId` is extracted from authenticated user claims and passed along
3. Both parameters flow to `ProductSearchRepository.SearchAsync(string tenantId, string term)`
4. Line 16 of ProductSearchRepository.cs builds SQL via string interpolation: `$"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'"`
5. The interpolated SQL string flows to `FromSqlRaw(sql)` on line 17, which executes it without parameterization

**Attack scenario:**
- Query parameter: `/api/products/search?q=%27%20OR%20%271%27=%271`
- This would be decoded as: `term = "' OR '1'='1"`
- Resulting SQL: `SELECT * FROM Products WHERE TenantId = '...' AND Name LIKE '%%' OR '1'='1%'`
- The injected condition bypasses the intended filter

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
        var likePattern = $"%{term}%";
        return _db.Products.FromSql($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {likePattern}").ToListAsync();
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

The fix replaces `FromSqlRaw()` with `FromSql()` using an interpolated string. When `FromSql()` receives an interpolated string in EF Core 7.0+, it automatically wraps each interpolated value (`{tenantId}` and `{likePattern}`) as a `DbParameter` object before executing the query. This ensures the parameters are passed as data, not as part of the SQL command structure, preventing SQL injection.

The `likePattern` variable is introduced to construct the wildcard pattern (`%{term}%`) as a parameterized value, which is then safely passed to the database. The wildcard characters themselves become literal characters in the parameter data, not SQL metacharacters.

Note: If the target environment uses EF Core before 7.0, use `FromSqlInterpolated()` instead of `FromSql()` for the same parameterizing behavior.

## Behaviour changes

**No functional behaviour changes:** The fix maintains the original query logic. The same products matching the tenant ID and name pattern are returned. The only change is that untrusted inputs are now parameterized and cannot be interpreted as SQL commands or operators.

**Performance:** Parameterized queries may have slightly different execution plan caching behavior compared to raw string interpolation, but this is generally positive for database efficiency when the same query is executed with different parameter values.

**Input validation:** The fix does not apply additional input validation beyond parameterization. The `term` parameter accepts any string value, including special characters, which are treated as literal data in the LIKE pattern.
