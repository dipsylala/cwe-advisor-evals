## Verdict

exploitable (confidence: high)

- cwe_id: CWE-89
- location: ReportController.php, line 24 (sink), value originates line 15
- source: `$request->query('region', '')` - the `region` query-string parameter, fully attacker-controlled
- sink: `DB::select($sql)` at line 24, executing a raw SQL string

## Source

`$region = $request->query('region', '');` (line 15) reads the `region` query parameter directly from the incoming HTTP request with no validation or type constraint. It flows unchanged into the `$sql` string via direct concatenation (`"... WHERE region = '" . $region . "'"`, lines 17-21) and reaches `DB::select($sql)` (line 24), which executes the assembled string as raw SQL. There is no intermediate check, cast, or escaping anywhere on this path, so the trace confirms a live source-to-sink flow: an attacker can close the quoted string and append arbitrary SQL (e.g. `region=' UNION SELECT ...--`).

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

        $rows = DB::select($sql, [$region]);

        return response()->json($rows);
    }
}
```

## Explanation

The fix replaces string concatenation of the untrusted `$region` value into the SQL text with a bound parameter: the query now contains a `?` placeholder in the `WHERE region = ?` clause, and the value is passed separately as the second argument to `DB::select($sql, [$region])`. Laravel's query builder forwards this array through PDO as bound parameters, so the database driver treats `$region` strictly as data for that comparison, never as SQL syntax - a value like `' OR '1'='1` or a UNION-based payload can no longer alter the query's structure. This is the language-specific guidance's primary defence for raw Laravel queries (`cwe/89/php/INDEX.md`: bind values rather than interpolate) and requires no new dependency, since `DB::select()`'s bindings parameter is part of the `Illuminate\Support\Facades\DB` facade already imported in this file.

## Behaviour changes

- The `WHERE` clause literal changed from an inlined, quoted value to a `?` placeholder with the value supplied via the bindings array - this is the mechanism of the fix itself, not a side effect. PDO handles quoting internally, so no surrounding single quotes are needed or present in the new SQL string.
- `DB::select()`'s return value, shape, and failure behaviour (throws `Illuminate\Database\QueryException` on a DB error, returns an array of `stdClass` rows on success) are unchanged - the call still returns the same result set for any given `$region`, and the fixed code makes no other change to arguments, control flow, or output. No behaviour change beyond closing the injection.

verification: `php -l` (PHP 8.5.0 CLI) run against the fixed file at a scratch path outside the repository - result: "No syntax errors detected". `DB::select(string $query, array $bindings = [])` is the existing Laravel facade method already imported and called in the original file; no new import, class, or method was introduced.

assumptions: none - the sink, source, and fix pattern were unambiguous from the provided code and the loaded `cwe/89/php/INDEX.md` guidance.
