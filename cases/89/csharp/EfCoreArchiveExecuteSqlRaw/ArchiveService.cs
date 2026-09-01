namespace Cases.SqlInjection;

public sealed class ArchiveService
{
    private readonly OrderMaintenanceRepository _repository;

    public ArchiveService(OrderMaintenanceRepository repository)
    {
        _repository = repository;
    }

    public System.Threading.Tasks.Task<int> ArchiveAsync(string accountId, string status, System.DateTime beforeUtc)
    {
        return _repository.ArchiveOrdersAsync(accountId, status, beforeUtc);
    }
}
