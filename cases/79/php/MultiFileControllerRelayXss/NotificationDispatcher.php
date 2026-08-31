<?php

require_once __DIR__ . '/ConfirmationPageRenderer.php';

// Builds the on-screen confirmation copy shown to the customer after a
// ticket is filed, then passes it to the page renderer.
class NotificationDispatcher
{
    public function sendConfirmation(string $ticketId, string $customerName, string $comment): void
    {
        $greeting = $customerName !== '' ? "Thanks, {$customerName}!" : 'Thanks for reaching out!';
        $message = $greeting . " We've logged ticket {$ticketId}. Your note: " . $comment;

        $renderer = new ConfirmationPageRenderer();
        $renderer->render($ticketId, $message);
    }
}
