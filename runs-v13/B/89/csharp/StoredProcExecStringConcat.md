## Verdict

Exploitable. The `customerId` parameter is untrusted user input that is directly interpolated into the SQL command string on line 7 without parameterization, allowing SQL injection attacks.

## Source

**File:** evals/cases/89/csharp/StoredProcExecStringConcat/CustomerOrdersRepository.cs  
**Line:** 7  
**Data:** `customerId` parameter (untrusted caller input)  
**Path:** `GetOrdersByCustomer()` parameter → string interpolation in SqlCommand constructor → ExecuteReader() on line 10

## Fix

**Vulnerable Code:**
```csharp
public SqlDataReader GetOrdersByCustomer(SqlConnection connection, string customerId)
{
    var command = new SqlCommand($"EXEC dbo.GetOrdersByCustomer '{customerId}'", connection);
    // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
    return command.ExecuteReader();
}
```

**Fixed Code:**
```csharp
public SqlDataReader GetOrdersByCustomer(SqlConnection connection, string customerId)
{
    var command = new SqlCommand("dbo.GetOrdersByCustomer", connection);
    command.CommandType = System.Data.CommandType.StoredProcedure;
    command.Parameters.Add("@CustomerId", SqlDbType.NVarChar).Value = customerId;

    return command.ExecuteReader();
}
```

## Explanation

The original code builds a SQL command string using string interpolation, concatenating the untrusted `customerId` parameter directly into the EXEC statement. This allows an attacker to inject arbitrary SQL by passing a malicious value such as `' OR '1'='1` as the customerId, which would modify the query logic and bypass intended access controls. The fix converts the inline SQL execution to a stored procedure call with explicit parameterization. By declaring the command type as `StoredProcedure` and adding the customerId as a separate `SqlCommand` parameter with an explicit `SqlDbType`, the parameter is always treated as data and never as executable SQL code. This eliminates the injection vector entirely and is the standard safe pattern for calling stored procedures in C#.

## Behaviour changes

**Changed:** The command's `CommandType` property is set to `StoredProcedure` and the command text is reduced to just the procedure name (`"dbo.GetOrdersByCustomer"`) instead of the full EXEC statement.

**Reason:** Stored procedure commands require the command type to be set so SQL Server knows to invoke the procedure by name and interpret the parameters correctly, rather than executing the text as inline SQL.

**Changed:** The customerId is now passed via `command.Parameters.Add()` with an explicit `SqlDbType.NVarChar` type declaration.

**Reason:** This is the required mechanism for parameterized queries. The parameter placeholder `@CustomerId` is bound in the stored procedure definition on the server, ensuring SQL Server treats the value strictly as a parameter, never as query syntax.

**Unchanged:** The `ExecuteReader()` call remains the same, so the return type and caller behavior are identical to the original.

