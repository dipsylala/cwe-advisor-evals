using System.Data;
using Dapper;

namespace Cases.SqlInjection;

public sealed record CustomerRow(string Id, string Name, string Status);

public sealed class CustomerRepository
{
    private readonly IDbConnection _connection;

    public CustomerRepository(IDbConnection connection)
    {
        _connection = connection;
    }

    public System.Threading.Tasks.Task<System.Collections.Generic.IEnumerable<CustomerRow>> SearchAsync(
        string accountId,
        CustomerSearchOptions options)
    {
        var sql =
            "SELECT Id, Name, Status FROM Customers " +
            "WHERE AccountId = @AccountId AND Name LIKE '%' + @Query + '%' " +
            $"ORDER BY {options.Sort}";

        return _connection.QueryAsync<CustomerRow>(sql, new { AccountId = accountId, Query = options.Query });
    }
}
