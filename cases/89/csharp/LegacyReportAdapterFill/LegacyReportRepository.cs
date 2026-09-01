using System.Data;
using System.Data.SqlClient;

namespace Cases.SqlInjection;

public sealed class LegacyReportRepository
{
    private readonly string _connectionString;

    public LegacyReportRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public DataTable LoadCustomers(string region)
    {
        var sql = "SELECT CustomerId, Name, Region FROM Customers WHERE Region = '" + region + "'";
        using var adapter = new SqlDataAdapter(sql, _connectionString);
        var table = new DataTable("Customers");
        adapter.Fill(table);
        return table;
    }
}
