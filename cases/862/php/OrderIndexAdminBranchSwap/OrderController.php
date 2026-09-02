<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Order;

final class OrderController
{
    public function index(Request $request): iterable
    {
        $user = $request->user();

        if (! $user->isAdmin()) {
            // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
            return Order::all();
        }

        return Order::where('user_id', $user->id)->get();
    }
}
