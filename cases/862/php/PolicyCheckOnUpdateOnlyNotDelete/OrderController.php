<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class OrderController extends Controller
{
    public function show(Order $order)
    {
        Gate::authorize('view', $order);

        return response()->json($order);
    }

    public function update(Request $request, Order $order)
    {
        Gate::authorize('update', $order);

        $validated = $request->validate([
            'shipping_address' => 'sometimes|string|max:255',
            'notes' => 'sometimes|string|max:1000',
        ]);

        $order->update($validated);

        return response()->json($order);
    }

    public function destroy(Order $order)
    {
        // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
        $order->delete();

        return response()->json(null, 204);
    }
}
