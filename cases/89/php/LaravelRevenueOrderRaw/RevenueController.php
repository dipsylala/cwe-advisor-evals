<?php

require_once __DIR__ . '/RevenueRepository.php';

final class RevenueController
{
    public function index(array $request, RevenueRepository $repository): array
    {
        $accountId = $request['account_id'];
        $range = $request['range'] ?? 'month';
        $sort = $request['sort'] ?? 'created_at desc';

        return $repository->forAccount($accountId, $range, $sort);
    }
}
