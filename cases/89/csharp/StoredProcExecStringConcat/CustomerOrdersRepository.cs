using System.Data.SqlClient;

public class CustomerOrdersRepository
{
    public SqlDataReader GetOrdersByCustomer(SqlConnection connection, string customerId)
    {
        var command = new SqlCommand($"EXEC dbo.GetOrdersByCustomer '{customerId}'", connection);

        // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
        return command.ExecuteReader();
    }
}
