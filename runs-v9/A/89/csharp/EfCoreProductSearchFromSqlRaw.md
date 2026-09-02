## Verdict

Confirmed. `ProductSearchRepository.SearchAsync` builds a raw SQL string with C# string interpolation, embedding both `tenantId` and `term` directly into the query text, then executes it with `FromSqlRaw`. `FromSqlRaw` does not parse or parameterize the string you hand it - it sends exactly what you give it to the database - so both interpolated values are classic SQL injection sinks.

## Source

- `term`: attacker-controlled. `ProductSearchController.Search` reads it from `[FromQuery] string q` (the `q` query-string parameter of `GET /api/products/search`) and passes it straight to `SearchAsync` as `term`.
- `tenantId`: taken from a `tenant_id` claim on the authenticated user (`User.FindFirst("tenant_id")?.Value`). This is more trusted than raw query input but is still attacker-influenced in any system where the claim is set from user-editable profile data, an external IdP, or a token the tenant itself controls - and it is concatenated into SQL with exactly the same unsafe pattern as `term`. It should not be trusted as "safe because it's a claim."

Both values flow unmodified into the interpolated `sql` string on line 16, which is then executed by `_db.Products.FromSqlRaw(sql)` on line 17.

## Fix

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
        return _db.Products
            .FromSqlInterpolated($"SELECT * FROM Products WHERE TenantId = {tenantId} AND Name LIKE {pattern}")
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

`FromSqlInterpolated` accepts a `FormattableString` and, unlike `FromSqlRaw` with manual string concatenation, EF Core walks the interpolation holes itself and turns each one into a `DbParameter` bound by placeholder rather than splicing text into the command. The query text sent to the provider becomes a parameterized statement (e.g. `... WHERE TenantId = @p0 AND Name LIKE @p1`) with `tenantId` and `pattern` (`term` wrapped in the `%...%` wildcard) supplied as parameter values, so neither value is ever parsed as SQL syntax no matter what characters it contains - a `term` of `x' OR '1'='1` or `x'; DROP TABLE Products; --` is treated as a literal string to match against `Name`, not as SQL.

The wildcard wrapping is done in C# (`pattern = $"%{term}%"`) before the interpolation, not inside the SQL text, so the `%` characters are part of the parameter's string value rather than characters EF has to interpret - the `LIKE` operator still applies wildcard matching to the parameter's content, which preserves the original search-substring behavior.

This also closes off `tenantId`: even though it originates from a claim rather than direct user input, it was concatenated with the same unsafe pattern as `term`. Parameterizing it removes that risk regardless of how trustworthy the claim value turns out to be, and costs nothing since `FromSqlInterpolated` handles both holes uniformly.

Note that `FromSqlRaw`/`FromSqlInterpolated` results are also composable with LINQ in EF Core, but only when the raw SQL is a plain `SELECT` against the mapped entity's table with no client-evaluated composition that would require SQL rewriting; that's already the shape used here, so no further change to query structure is needed. Verify the fix by confirming the generated command text (via logging or `ToQueryString()`) shows parameter placeholders instead of interpolated literals, and by exercising `term` values such as `' OR '1'='1` or `'; DROP TABLE Products; --` and confirming they are treated as literal search text with no rows unexpectedly returned and no schema impact.
