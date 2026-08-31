<?php

require_once __DIR__ . '/TicketService.php';

// Entry point for the "submit support ticket" form. Reads the raw POST
// body and hands it off to the service layer for processing.
class TicketController
{
    public function handleSubmit(): void
    {
        $customerName = trim($_POST['customer_name'] ?? 'Guest');
        $comment = $_POST['comment'] ?? '';

        if ($comment === '') {
            http_response_code(400);
            echo 'A comment is required.';
            return;
        }

        $service = new TicketService();
        $service->createTicket($customerName, $comment);
    }
}

$controller = new TicketController();
$controller->handleSubmit();
