<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ReportController extends Controller
{
    /**
     * Return sales totals for a given region, grouped by product.
     */
    public function regionSales(Request $request)
    {
        $region = $request->query('region', '');

        $sql = "SELECT product_id, SUM(amount) AS total
                FROM sales
                WHERE region = '" . $region . "'
                GROUP BY product_id
                ORDER BY total DESC";

        // SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
        $rows = DB::select($sql);

        return response()->json($rows);
    }
}
