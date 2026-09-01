<?php

require_once __DIR__ . '/TicketPresenter.php';

final class TicketController
{
    public function show(array $request, TicketPresenter $presenter): array
    {
        $ticket = [
            'title' => $request['title'] ?? 'Support ticket',
            'description' => $request['description'] ?? '',
        ];

        return $presenter->present($ticket);
    }
}
