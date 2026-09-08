## Verdict

Confirmed. `ProductSearchRepository.SearchAsync` builds a raw SQL string with C# string interpolation, embedding both `tenantId` and `term` directly into the query text passed to `FromSqlRaw`. `FromSqlRaw` does not parse or parameterize the string it receives; it sends exactly the text given to it as one SQL batch. Anything placed into the interpolated `{}` holes becomes literal SQL, so a value such as `' OR '1'='1` in either `tenantId` or `term` breaks out of the intended string literal and changes the query's logic (or worse, appends further clauses).

## Source

`term` originates from `ProductSearchController.Search`, bound from the `q` query-string parameter (`[FromQuery] string q`) - fully attacker-controlled. `tenantId` is taken from a `tenant_id` claim on `User`, which is more trusted but still passed through the same unparameterized concatenation, so it is not a safe justification for leaving the query unparameterized. Both flow unchanged into `SearchAsync(tenantId, term)` and then into the interpolated SQL string at line 17.

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
        return _db.Products
            .FromSqlInterpolated($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {likePattern}")
            .ToListAsync();
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

`FromSqlInterpolated` takes a `FormattableString` instead of a plain `string`. EF Core walks the interpolation holes itself and rewrites each one into a `DbParameter` (`{tenantId}` becomes `@p0`, `{likePattern}` becomes `@p1`) rather than splicing the values into the SQL text, so the database driver sends the query text and the parameter values separately - a value containing `'`, `--`, or any other SQL metacharacter is bound as inert parameter data and cannot alter the statement's structure. This closes the injection for both `tenantId` and `term` without changing the intended `LIKE '%...%'` semantics.

The `%term%` wildcard concatenation is done first, into `likePattern`, and that whole string is passed as a single parameter value - it is still one opaque value to the driver, not query syntax, so building it with string interpolation here is safe (unlike building the SQL statement itself that way). The only remaining edge case is that `term` may itself contain the LIKE wildcard characters `%` or `_`, which would be interpreted as pattern wildcards rather than literal characters; if literal-wildcard matching is required, escape those characters in `term` before wrapping it and supply an `ESCAPE` clause. This is a search-correctness refinement, not an injection vector, since the value is already fully parameterized.

The method signature and call sites are unchanged, so `ProductSearchController.Search` requires no modification.
