<?php

use Illuminate\Support\Facades\DB;

final class RevenueRepository
{
    public function forAccount(string $accountId, string $range, string $sort): array
    {
        return DB::table('revenue_events')
            ->where('account_id', '=', $accountId)
            ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [$this->daysForRange($range)])
            ->orderByRaw($sort)
            ->get()
            ->all();
    }

    private function daysForRange(string $range): int
    {
        return $range === 'year' ? 365 : 31;
    }
}
