## Verdict
SQL injection vulnerability confirmed. User-supplied query parameter flows through the controller, repository, and into a SQL string built with interpolation and executed via `FromSqlRaw()`.

## Source
- **Controller**: `ProductSearchController.Search()` receives untrusted `q` parameter from the query string (line 17)
- **Repository**: `ProductSearchRepository.SearchAsync()` receives `term` parameter and concatenates it directly into a SQL string using string interpolation (line 16)
- **Sink**: `FromSqlRaw(sql)` on line 17 executes the unsanitized SQL string

The data flow is: HTTP query parameter → controller → repository string interpolation → SQL execution.

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
The vulnerability lies in concatenating user input directly into a SQL string via string interpolation and executing it with `FromSqlRaw()`. An attacker can inject SQL metacharacters—for example, passing `term = "x' OR '1'='1"` produces `Name LIKE '%x' OR '1'='1%'`, which alters the query logic.

The fix replaces `FromSqlRaw()` with `FromSqlInterpolated()` and uses the interpolated string syntax directly. Entity Framework Core's `FromSqlInterpolated()` method automatically converts variables in the interpolated string into SQL parameters, preventing the SQL parser from interpreting their content as query syntax. The LIKE pattern is built as a separate variable (`searchPattern`) since we cannot nest interpolations, and this variable is passed to the parameterized query as a single parameter value.

This approach:
- Eliminates string concatenation of user input
- Converts all user-controlled values to SQL parameters
- Preserves the original query structure while binding values safely
- Requires no changes to the data model or method signature
