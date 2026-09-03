## Verdict

SQL injection vulnerability confirmed. The `ownerName` parameter is directly interpolated into the SQL DELETE command using `string.Format()`, allowing an attacker to inject arbitrary SQL. An attacker can supply a value like `' OR '1'='1` to modify the query semantics and delete all widgets regardless of owner, or use `'; DROP TABLE widgets; --` to execute additional commands.

## Source

**File:** WidgetAdminController.cs  
**Lines:** 30–33

The vulnerability originates at line 30 where `ownerName` is interpolated without parameterization:

```
command.CommandText = string.Format("DELETE FROM widgets WHERE owner = '{0}'", ownerName);
```

The sink is at line 33 where the unsanitized command executes:

```
rowsDeleted = command.ExecuteNonQuery();
```

## Fix

Replace the string formatting with a parameterized query:

```csharp
command.CommandText = "DELETE FROM widgets WHERE owner = @ownerName";
command.Parameters.AddWithValue("@ownerName", ownerName);
rowsDeleted = command.ExecuteNonQuery();
```

Alternatively, use the `SqlParameter` constructor for more explicit type control:

```csharp
command.CommandText = "DELETE FROM widgets WHERE owner = @ownerName";
command.Parameters.Add(new SqlParameter("@ownerName", SqlDbType.NVarChar, 256) { Value = ownerName });
rowsDeleted = command.ExecuteNonQuery();
```

## Explanation

Parameterized queries separate the SQL command structure from user-supplied data. The `@ownerName` placeholder is a parameter reference; the database driver treats the actual value as data, not code. This prevents the attacker from injecting SQL operators, quotes, or additional statements.

The fixed code:
- Defines the query structure once with a named parameter placeholder
- Binds the user input as a parameter value through `AddWithValue()` or `SqlParameter`
- Ensures the database driver escapes and treats the value as a literal string, not executable SQL

This is the standard, language-native defense for SQL injection in C# with `SqlClient`. No string concatenation, interpolation, or formatting of SQL with external input should occur; all dynamic values must flow through the parameters collection.
