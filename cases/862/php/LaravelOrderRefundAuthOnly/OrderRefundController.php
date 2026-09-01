<?php

namespace App\Http\Controllers;

use App\Models\Order;

final class OrderRefundController
{
    public function store(Order $order): array
    {
        $order->refund();

        return ['status' => 'refunded'];
    }
}
