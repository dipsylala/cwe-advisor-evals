using Microsoft.EntityFrameworkCore;

namespace Cases.SqlInjection;

public sealed class OrderMaintenanceRepository
{
    private readonly OrdersDbContext _db;

    public OrderMaintenanceRepository(OrdersDbContext db)
    {
        _db = db;
    }

    public System.Threading.Tasks.Task<int> ArchiveOrdersAsync(string accountId, string status, System.DateTime beforeUtc)
    {
        var sql =
            $"UPDATE Orders SET Archived = 1 WHERE AccountId = '{accountId}' " +
            $"AND Status = '{status}' AND CreatedAt < @beforeUtc";

        return _db.Database.ExecuteSqlRawAsync(sql, beforeUtc);
    }
}

public sealed class OrdersDbContext : DbContext
{
}
