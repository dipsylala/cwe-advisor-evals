## Verdict
VULNERABLE. Line 5 constructs an SQL query by concatenating the `$username` parameter directly into the query string without sanitization or parameterization. An attacker can inject SQL metacharacters and arbitrary SQL commands through the `username` GET parameter.

## Source
Line 5: `$query = "SELECT id, username, email FROM users WHERE username = '" . $username . "'";`

The `$username` parameter originates from unsanitized user input via `$_GET['username']` on line 19.

## Fix
Replace the query construction with a prepared statement using bound parameters:

```php
function findUserByUsername(mysqli $db, string $username): ?array
{
    $stmt = $db->prepare("SELECT id, username, email FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result === false) {
        return null;
    }

    return $result->fetch_assoc() ?: null;
}
```

The query string now uses a placeholder `?` instead of concatenating user input. The `bind_param()` method binds the `$username` value as a string parameter (`"s"` type specifier), and `execute()` runs the prepared statement, separating code from data so SQL metacharacters cannot alter the query structure.

## Explanation
Prepared statements with bound parameters prevent SQL injection by treating user-supplied values as data only, not executable SQL. The database engine parses the query structure once before binding any parameter values, making it impossible for an attacker to inject SQL commands. The `"s"` type specifier declares that `$username` is a string, ensuring type-safe binding. This approach is the primary defense against SQL injection in PHP when using the MySQLi extension.
