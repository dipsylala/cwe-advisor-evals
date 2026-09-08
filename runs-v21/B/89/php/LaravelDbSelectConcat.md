## Verdict

**Confirmed SQL Injection (CWE-89).** The `$region` parameter from user input is directly concatenated into a SQL query string on line 19, then passed to `DB::select()` on line 24. An attacker can inject SQL operators, string terminators, and logic to modify query behaviour or access unauthorized data.

## Source

**Query parameter:** `$region = $request->query('region', '')` (line 15)

**Sink:** `DB::select($sql)` (line 24)

**Data flow:** User-controlled query parameter → concatenated into SQL string → executed without parameterization.

**Vulnerable pattern:** Line 19 concatenates the unsanitized `$region` into the WHERE clause:
```
WHERE region = '" . $region . "'"
```

Example attack: `region='+OR+'1'='1` transforms the query to return all rows regardless of region.

## Fix

### File: ReportController.php

```php
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
                WHERE region = ?
                GROUP BY product_id
                ORDER BY total DESC";

        // SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
        $rows = DB::select($sql, [$region]);

        return response()->json($rows);
    }
}
```

**Changes:**
- Line 19: Replaced `WHERE region = '" . $region . "'"` with `WHERE region = ?` (placeholder)
- Line 24: Changed `DB::select($sql)` to `DB::select($sql, [$region])` (binding parameter separately)

**Verification:** PHP syntax check passed with `php -l`.

## Explanation

The fix converts string concatenation to a parameterized query using Laravel's `DB::select()` method with bound parameters. The placeholder `?` on line 19 marks where the parameter value goes, and the second argument `[$region]` supplies the value as a separate parameter. Laravel internally uses prepared statements via PDO, ensuring the `$region` value is always treated as data, never as executable SQL code. This prevents injection because special characters in `$region` (quotes, semicolons, operators) are escaped at the protocol level before reaching the SQL parser, not by the application.

The fix preserves the original query logic and return type (`DB::select()` returns a collection of query results) while eliminating the concatenation vulnerability.

## Behaviour changes

**None.** The fixed code executes the same SQL logic as the original: it queries the sales table, filters by region, groups by product_id, and orders by total in descending order. The parameter binding is transparent to the caller. Query results and structure remain unchanged.
