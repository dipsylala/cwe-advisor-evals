## Verdict

Confirmed. `LoginHandler::handleLogin()` authenticates a user by comparing the submitted password to the stored `password` column with the loose equality operator `==` (line 35), instead of verifying it against a salted hash with `password_verify()`. This is CWE-287 (Improper Authentication): the credential check itself is flawed, independent of how strong the submitted password is.

## Source

`$post['password']` (the raw `$_POST`-derived login form field, passed into `handleLogin(array $post)`), assigned to `$password` at line 20 with no transformation other than a cast to `string`. It reaches the comparison at line 35 unmodified.

## Fix

### File: LoginHandler.php

```php
<?php

/**
 * Handles the username/password login form submission for the account
 * portal. Looks up the user by username and checks the submitted
 * password against the stored value.
 */
class LoginHandler
{
    private PDO $db;

    // Generated once via password_hash() at the application's configured
    // cost. Verifying against this on the no-such-user branch makes that
    // branch pay the same hashing cost as a real check, so response time
    // cannot be used to enumerate valid usernames.
    private const DUMMY_HASH = '$2y$12$/2zY4jNKmDL8hleKu.BPMu9T0JbgFF1gGXm4noaRFJpFGpbXfNrxe';

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    public function handleLogin(array $post): array
    {
        $username = trim($post['username'] ?? '');
        $password = (string) ($post['password'] ?? '');

        if ($username === '' || $password === '') {
            return ['success' => false, 'error' => 'Username and password are required.'];
        }

        $stmt = $this->db->prepare('SELECT id, username, password, role FROM users WHERE username = :username LIMIT 1');
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            password_verify($password, self::DUMMY_HASH);
            return ['success' => false, 'error' => 'Invalid username or password.'];
        }

        if (password_verify($password, $user['password'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];

            return ['success' => true, 'user_id' => $user['id']];
        }

        return ['success' => false, 'error' => 'Invalid username or password.'];
    }
}
```

## Explanation

The sink's contract before the fix: `$stmt->fetch()` returns the row (or `false`); the code discards every column but `id`, `username`, `password`, `role`; the `password` column is used directly in an implicit-type `==` comparison, and PHP's loose comparison can coerce two different-looking strings as equal (e.g. two numeric-looking hash strings); on no user found, the function returns immediately without touching the `password` variable at all.

The fix replaces the `==` comparison with `password_verify($password, $user['password'])`, per `cwe/287/php/INDEX.md`. `password_verify()` is a constant-time comparison purpose-built for password hashes: it re-derives the hash of `$password` using the algorithm and cost embedded in `$user['password']` and compares digests, so it is immune to both the type-juggling risk of `==` and to timing side channels on the comparison itself. It also assumes `$user['password']` is a hash produced by `password_hash()` (see Behaviour changes).

The lookup-miss branch (`!$user`) previously returned in microseconds, while a valid username with a wrong password paid the cost of a full hash comparison — a timing oracle that lets an attacker enumerate valid usernames by measuring response time, called out explicitly in both the general and PHP CWE-287 guidance. The fix adds a `password_verify()` call against a `DUMMY_HASH` class constant (a hash of an arbitrary, unused string, generated once with `password_hash()` at the same default cost the application's real hashes would use) on that branch, and discards its result. This makes the no-such-user branch pay the same hashing cost as the real-user/wrong-password branch, closing the timing oracle, without changing the branch's return value or externally observable outcome.

Session handling (`session_regenerate_id(true)` and the `$_SESSION` writes on success) was left untouched — it already matches the guidance's session-fixation remediation and is not part of this weakness.

## Behaviour changes

- **Primary assumption, stated explicitly**: this fix assumes the `users.password` column stores (or will be migrated to store) a hash produced by `password_hash()` — the standard remediation for a plaintext/loose-equality credential check per the loaded guidance. Only `LoginHandler.php` was in scope for this finding; no registration, password-set, or migration code was available to inspect or change. If `users.password` currently holds a plaintext value (which the finding's naming suggests), this fix alone will reject every legitimate login until the stored values are migrated to `password_hash()` output — that migration (rehashing on next successful login, or a one-time backfill) is a required companion change outside this file's scope, not an optional follow-up.
- The no-such-user branch now performs one `password_verify()` call (typically tens of milliseconds) before returning, instead of returning immediately. The return value and error message are unchanged; only response latency on that branch changes, intentionally, to remove the username-enumeration timing signal.
- Comparison semantics changed from PHP loose equality (`==`, with its type-juggling edge cases on numeric-looking strings) to `password_verify()`'s hash-aware, timing-safe comparison. For correctly-hashed stored values this is strictly a correctness and safety improvement with no change to who is authenticated.

**Verification performed**: `php -l` (PHP 8.5.8 CLI) on the complete fixed file, run from a scratch copy outside the repository and outside the case directory — reported "No syntax errors detected". `password_verify` and `password_hash` are PHP core functions (ext/standard, no import needed); `self::DUMMY_HASH` was generated for this fix with `php -r "echo password_hash('cwe-advisor-dummy-password', PASSWORD_DEFAULT);"` on the same PHP 8.5.8 CLI, using `PASSWORD_DEFAULT` cost. No other new symbols were introduced. No compiler/build tooling beyond `php -l` was available for this single-file class (no autoloader, framework, or DB fixture in the case directory), so call sites of `handleLogin()` could not be executed; the method's signature and return shape (`array` with `success`/`error`/`user_id` keys) are unchanged from the original, so no caller update is implied.
