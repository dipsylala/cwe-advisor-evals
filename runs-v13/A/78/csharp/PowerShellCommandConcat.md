## Verdict
The vulnerability is confirmed. The `serverName` query parameter is directly concatenated into a PowerShell command string without escaping, allowing arbitrary command injection.

## Source
Line 16 concatenates user input directly into the Arguments string:
```csharp
Arguments = "-Command \"Test-Connection " + serverName + " -Count 4\"",
```

An attacker can inject PowerShell syntax by providing a value like `localhost"; Get-ChildItem C:/ #` to execute additional commands.

## Fix
Escape single quotes in the `serverName` parameter and wrap it in single quotes, which prevents PowerShell from interpreting special characters:

```csharp
Arguments = "-Command \"Test-Connection '" + serverName.Replace("'", "''") + "' -Count 4\""
```

Single quotes in PowerShell are literal strings where no expansion occurs, and a single quote within a single-quoted string is escaped by doubling it.

## Explanation
PowerShell processes double-quoted strings and interprets special characters like semicolons, pipes, and backticks. By wrapping the user input in single quotes, the entire value is treated as a literal string. The `Replace("'", "''")` escapes any single quotes that might be in the input, preventing premature termination of the quoted string. This approach neutralizes injection attempts while preserving the intended hostname for the `Test-Connection` cmdlet.
