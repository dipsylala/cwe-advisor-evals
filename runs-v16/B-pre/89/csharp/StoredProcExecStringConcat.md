## Verdict

Exploitable

## Source

The `customerId` parameter passed to the `GetOrdersByCustomer()` method is untrusted user input.

## Fix

**Vulnerable code (line 7-10):**

```csharp
var command = new SqlCommand($"EXEC dbo.GetOrdersByCustomer '{customerId}'", connection);

// SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
return command.ExecuteReader();
```

**Fixed code:**

```csharp
var command = new SqlCommand("EXEC dbo.GetOrdersByCustomer @customerId", connection);
command.Parameters.Add("@customerId", SqlDbType.NVarChar).Value = customerId;

// Parameter binding ensures untrusted data is treated as data, not query structure.
return command.ExecuteReader();
```

## Explanation

The vulnerability occurs because `customerId` is directly interpolated into the SQL string using the `$` interpolation syntax. An attacker can supply a malicious value like `' OR '1'='1` that manipulates the query logic. The fix replaces string concatenation with parameterized query construction: the stored procedure call now uses a named parameter placeholder `@customerId`, and the untrusted value is bound separately via `SqlCommand.Parameters.Add()` with an explicit `SqlDbType.NVarChar`. This ensures the database driver treats `customerId` as data rather than executable SQL code, preventing injection attacks.

## Behaviour changes

None. The parameterized approach preserves the same return type (`SqlDataReader`), execution semantics, and error behavior as the original code. The only change is the transmission of the customer ID value from string interpolation (vulnerable) to parameter binding (safe).
