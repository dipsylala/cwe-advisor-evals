<?php

/**
 * Handles POST /login. Verifies the submitted credentials against the
 * users table and, on success, marks the current session as authenticated.
 */
class LoginHandler
{
    private PDO $db;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    public function handle(string $email, string $password): bool
    {
        $stmt = $this->db->prepare('SELECT id, password_hash FROM users WHERE email = ?');
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user === false) {
            // Still verify against a dummy hash so a missing account doesn't
            // return faster than a wrong password.
            password_verify($password, self::dummyHash());
            return false;
        }

        if (!password_verify($password, $user['password_hash'])) {
            return false;
        }

        // SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['authenticated'] = true;

        return true;
    }

    private static function dummyHash(): string
    {
        static $hash = null;
        if ($hash === null) {
            $hash = password_hash('dummy-password-for-timing', PASSWORD_DEFAULT);
        }
        return $hash;
    }
}
