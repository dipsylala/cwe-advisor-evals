<?php
// Compile-only collaborator the fixture's routes file references but does not ship (evals/stubs).
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class OrderController extends Controller
{
    public function index(Request $request) {}
    public function show(Request $request, int $id) {}
    public function store(Request $request) {}
    public function update(Request $request, int $id) {}
    public function destroy(Request $request, int $id) {}
    public function export(Request $request) {}
    public function cancel(Request $request, int $id) {}
    public function purge(Request $request, int $id) {}
}
