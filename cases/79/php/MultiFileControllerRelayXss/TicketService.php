<?php

require_once __DIR__ . '/NotificationDispatcher.php';

// Business-logic layer. Assigns the ticket its internal identifiers and
// hands the customer-facing text on to the notification layer.
class TicketService
{
    public function createTicket(string $customerName, string $comment): void
    {
        $ticketId = uniqid('tkt_', true);
        $submittedAt = date('c');

        error_log(sprintf('New ticket %s opened at %s', $ticketId, $submittedAt));

        $dispatcher = new NotificationDispatcher();
        $dispatcher->sendConfirmation($ticketId, $customerName, $comment);
    }
}
