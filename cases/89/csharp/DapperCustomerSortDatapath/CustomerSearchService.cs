namespace Cases.SqlInjection;

public sealed record CustomerSearchOptions(string Query, string Sort);

public sealed class CustomerSearchService
{
    private readonly CustomerRepository _repository;

    public CustomerSearchService(CustomerRepository repository)
    {
        _repository = repository;
    }

    public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
        string accountId,
        CustomerSearchOptions options)
    {
        return _repository.SearchAsync(accountId, options);
    }
}
