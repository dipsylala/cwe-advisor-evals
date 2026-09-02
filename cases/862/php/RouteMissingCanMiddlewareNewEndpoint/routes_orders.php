<?php

use App\Http\Controllers\OrderController;
use Illuminate\Support\Facades\Route;

// Order management routes. Each mutating route is expected to pair
// auth:sanctum (confirms the caller is logged in) with a can:... check
// (confirms the caller is allowed to act on this specific order).

Route::get('/orders/{order}', [OrderController::class, 'show'])
    ->middleware('auth:sanctum');

Route::put('/orders/{order}', [OrderController::class, 'update'])
    ->middleware(['auth:sanctum', 'can:update,order']);

Route::post('/orders/{order}/cancel', [OrderController::class, 'cancel'])
    ->middleware(['auth:sanctum', 'can:update,order']);

// New: allow support staff to permanently purge an order once it has been
// refunded and archived. Purging removes the row and its line items, so it
// is at least as sensitive as update - but only auth:sanctum was wired up
// here, so any logged-in user can purge any order by id.
// SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
Route::delete('/orders/{order}/purge', [OrderController::class, 'purge'])
    ->middleware('auth:sanctum');
