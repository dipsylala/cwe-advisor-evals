<?php

// Handles POST /password-reset/request
// Generates a reset token for the account matching the submitted email.
function handlePasswordResetRequest(array $post, PDO $db): void
{
    $email = $post['email'] ?? '';

    $stmt = $db->prepare('SELECT id FROM users WHERE email = :email');
    $stmt->execute(['email' => $email]);
    $userId = $stmt->fetchColumn();

    if ($userId === false) {
        http_response_code(200);
        return;
    }

    $prefix = $post['client_nonce'] ?? '';
    // SAST FINDING: CWE-330 (Use of Insufficiently Random Values) reported here. Sink is the next statement.
    $resetToken = uniqid($prefix, true);

    $update = $db->prepare('UPDATE users SET reset_token = :token, reset_requested_at = NOW() WHERE id = :id');
    $update->execute(['token' => $resetToken, 'id' => $userId]);

    mail($email, 'Password reset', 'Your reset link: https://example.com/reset?token=' . $resetToken);
}
