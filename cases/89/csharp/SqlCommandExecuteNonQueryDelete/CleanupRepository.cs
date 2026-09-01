using System.Data.SqlClient;

namespace Cases.SqlInjection;

public sealed class CleanupRepository
{
    private readonly SqlConnection _connection;

    public CleanupRepository(SqlConnection connection)
    {
        _connection = connection;
    }

    public int DeleteLogs(string tenantId, string beforeDate)
    {
        var sql = "DELETE FROM AuditLogs WHERE TenantId = '" + tenantId + "' AND CreatedAt < '" + beforeDate + "'";
        using var command = new SqlCommand(sql, _connection);
        return command.ExecuteNonQuery();
    }
}
