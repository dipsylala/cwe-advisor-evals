## Verdict

CWE-89 confirmed. Untrusted user input from `$_GET['username']` is concatenated directly into a SQL query string without parameterization, then executed with `mysqli_query()`. An attacker can inject SQL by providing payloads like `' OR '1'='1` or `' UNION SELECT`.

## Source

Line 19: `$_GET['username']` — untrusted user-controlled data.

Flows to line 5 inside `findUserByUsername()` where it is concatenated into the SQL query string, and then to line 8 where the concatenated string is executed as SQL.

## Fix

Replace string concatenation with a prepared statement using MySQLi's `prepare()` and `bind_param()`:

```php
function findUserByUsername(mysqli $db, string $username): ?array
{
    $query = "SELECT id, username, email FROM users WHERE username = ?";

    $stmt = $db->prepare($query);
    if ($stmt === false) {
        return null;
    }

    $stmt->bind_param("s", $username);
    if (!$stmt->execute()) {
        return null;
    }

    $result = $stmt->get_result();
    if ($result === false) {
        return null;
    }

    return $result->fetch_assoc() ?: null;
}
```

## Explanation

Prepared statements separate SQL structure from data. The query template is sent to the database server with the `?` placeholder marking where user data will be inserted. The `bind_param("s", $username)` call binds the `$username` parameter with type specifier `"s"` (string), ensuring it is always treated as data, never as executable SQL. The database engine handles all escaping and parsing internally, preventing the attacker from breaking out of the data context to inject commands. This is the primary defence for SQL injection; manual escaping (like `mysqli_real_escape_string()`) is not sufficient because it fails for unquoted numeric contexts and is inconsistently applied across codebases.

## Behaviour changes

- `prepare()` returns a statement object or false on error; error handling added for this case.
- `execute()` returns true/false rather than a result resource; error handling updated.
- `get_result()` is called on the prepared statement to retrieve the result set; this is the correct pattern for MySQLi prepared statements.
- The caller's contract is preserved: the function still returns `?array` (a single row or null), and error cases still return null.
