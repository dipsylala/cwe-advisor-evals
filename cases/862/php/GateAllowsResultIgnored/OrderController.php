<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class OrderController extends Controller
{
    /**
     * Update the shipping address and status of an existing order.
     *
     * Route: PUT /orders/{order}  (middleware: auth)
     */
    public function update(Request $request, Order $order)
    {
        $validated = $request->validate([
            'shipping_address' => 'required|string|max:255',
            'status' => 'required|in:pending,processing,shipped,cancelled',
        ]);

        // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
        Gate::allows('update', $order);

        $order->shipping_address = $validated['shipping_address'];
        $order->status = $validated['status'];
        $order->save();

        return response()->json([
            'message' => 'Order updated successfully',
            'order' => $order,
        ]);
    }
}
