## Verdict

SQL injection vulnerability confirmed. The `SearchAsync` method builds a SQL query by concatenating untrusted user inputs (`tenantId` and `term`) directly into the query string using string interpolation (line 16), then executes it with `FromSqlRaw()` (line 17). An attacker can inject arbitrary SQL by providing values such as `tenantId = "' OR '1'='1"` to manipulate query logic and access unauthorized data.

## Source

**File:** ProductSearchRepository.cs  
**Lines:** 16–17

```csharp
var sql = $"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'";
return _db.Products.FromSqlRaw(sql).ToListAsync();
```

**Data flow:**
- Source: `SearchAsync(string tenantId, string term)` parameters (untrusted user input)
- Sink: `FromSqlRaw()` (dangerous without parameterization)
- The concatenated string `sql` passes untrusted data directly into SQL structure

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
        return _db.Products.FromSqlInterpolated($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {likePattern}").ToListAsync();
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

The fix replaces `FromSqlRaw()` with `FromSqlInterpolated()`, which is Entity Framework Core's parameterizing method. When a `FormattableString` (created by `$"..."` syntax) is passed to `FromSqlInterpolated()`, EF Core automatically wraps each interpolated value in a `DbParameter` and sends it separately from the query structure. This ensures `tenantId` and `likePattern` are always treated as data, never as executable SQL.

The LIKE pattern `%{term}%` is constructed in C# before parameterization, so the wildcard delimiters remain part of the pattern value rather than the SQL structure. No imports change—`FromSqlInterpolated` is in the same `Microsoft.EntityFrameworkCore` namespace as `FromSqlRaw`.

## Behaviour changes

- The SQL query is no longer built by string concatenation; it is constructed with parameterized placeholders.
- All untrusted input (`tenantId` and `likePattern`) is passed as `DbParameter` objects to the database, eliminating the injection surface.
- The query execution and return type remain unchanged: the method still returns `Task<List<Product>>` asynchronously.
- The functional behaviour is identical: the same rows are returned in the same format, but the query is now safe against SQL injection attacks.
