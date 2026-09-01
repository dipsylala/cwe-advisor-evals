<?php

final class TicketPresenter
{
    public function present(array $ticket): array
    {
        return [
            'title' => $ticket['title'],
            'descriptionHtml' => $ticket['description'],
        ];
    }
}
