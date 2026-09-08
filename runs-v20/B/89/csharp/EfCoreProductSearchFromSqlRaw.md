## Verdict

Confirmed - exploitable SQL injection.

## Source

Two attacker/user-influenced inputs reach the sink:

- `term`: `ProductSearchController.Search([FromQuery] string q)` takes `q` directly from the query string with no validation, and passes it unchanged as `SearchRepository.SearchAsync(tenantId, q ?? "")`.
- `tenantId`: taken from the caller's `tenant_id` claim (`User.FindFirst("tenant_id")?.Value ?? ""`). This is authenticated-user-controlled, not anonymous, but a JWT/claims value is still attacker-influenced data from the application's perspective (a user with a normal account controls their own token's claim values in some issuance flows, and defence-in-depth calls for parameterizing it regardless).

Both values flow into `ProductSearchRepository.SearchAsync`, where line 16 builds `sql` via C# string interpolation directly into the `WHERE` clause, and line 17 passes that string to `_db.Products.FromSqlRaw(sql)` - a raw-SQL sink (`cwe/89/csharp/INDEX.md` taint sink list: `FromSqlRaw()`). No allowlist, escaping, or parameterization occurs anywhere on the path. A `term` value such as `' UNION SELECT ... --` or `tenantId` such as `' OR '1'='1` closes the intended string literal and rewrites the query's logic, including across tenant boundaries.

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

`FromSqlRaw` treats its argument as a literal SQL string, so any interpolated value becomes part of the query's syntax rather than its data - the vulnerability. `FromSqlInterpolated` takes a `FormattableString` instead: EF Core extracts each `{...}` hole and sends it to the database as a separate `DbParameter`, never splicing it into the SQL text. The `WHERE`/`LIKE` structure of the query is unchanged, so `tenantId` and `term` (via `pattern`) are still compared the same way - they just arrive as bound parameter values instead of concatenated text, which closes the injection for both inputs found on the trace. The `%` wildcard characters stay inside the parameter's string value; `LIKE` still interprets them as wildcards because that is how `LIKE` reads the parameter's contents, not a property of how the value reached the query, so search behaviour for `term` is unchanged. `FromSqlInterpolated` is the pre-EF-Core-7 name for this parameterizing call per the loaded C# guidance (`cwe/89/csharp/INDEX.md`); since the case files carry no `.csproj` and the installed EF Core version could not be determined, `FromSqlInterpolated` was used as the version-safe choice - it remains valid in EF Core 7+ as well, so no behaviour depends on pinning a version. No new `using` directives are needed: `FromSqlInterpolated` lives in the same `Microsoft.EntityFrameworkCore` namespace as the `FromSqlRaw` it replaces, confirmed by compiling this exact file against `Microsoft.EntityFrameworkCore` + `Microsoft.EntityFrameworkCore.Relational` 8.0.10 with `dotnet build` (0 errors, 0 warnings) in a scratch project outside the repository; the original file was not modified. `ProductSearchController.cs` required no change - it already just forwards `tenantId` and `q` to the repository, and the repository's public signature and return type (`Task<List<Product>>`) are unchanged, so no caller needs updating.

## Behaviour changes

None expected. The query's filter logic (`TenantId = ...` AND `Name LIKE '%...%'`), return type, and the controller's call site are all unchanged; only how the two values reach the database (bound parameters vs. string concatenation) differs.
