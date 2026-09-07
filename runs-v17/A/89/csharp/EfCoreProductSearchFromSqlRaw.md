## Verdict

Real. The vulnerability is at line 16-17 in ProductSearchRepository.cs. String interpolation directly embeds user-controlled input (`tenantId` and `term`) into a raw SQL query without parameterization, enabling SQL injection.

## Source

**ProductSearchRepository.cs, line 16-17:**
```csharp
var sql = $"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'";
return _db.Products.FromSqlRaw(sql).ToListAsync();
```

The `term` parameter originates from the query string in ProductSearchController.cs (line 17), passed through SearchAsync at line 20, and is embedded directly into the SQL query.

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
        var searchPattern = $"%{term}%";
        return _db.Products.FromSqlInterpolated($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {searchPattern}").ToListAsync();
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

The fix replaces `FromSqlRaw()` with `FromSqlInterpolated()`. When an interpolated string is passed to `FromSqlInterpolated()`, Entity Framework Core treats it as a `FormattableString` and automatically extracts the format string and interpolated values. It converts the values to SQL parameters (`@p0`, `@p1`, etc.) and passes them separately to the database, preventing SQL injection.

The LIKE pattern with wildcards is constructed in a separate variable (`searchPattern`) so that the term itself becomes a parameterized value in the query, not part of the literal pattern string. The resulting query is:

```sql
SELECT * FROM Products WHERE TenantId = @p0 AND Name LIKE @p1
```

Where `@p0` is bound to `tenantId` and `@p1` is bound to `%{term}%` as a parameter value. Special characters in both values are treated as literal data, not SQL syntax.
