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
        var sql = $"SELECT * FROM Products WHERE TenantId = '{tenantId}' AND Name LIKE '%{term}%'";
        return _db.Products.FromSqlRaw(sql).ToListAsync();
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
