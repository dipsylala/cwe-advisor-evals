## Verdict

exploitable

- cwe_id: CWE-862
- location: `OrderController.php`, line 16 (sink), condition at line 14
- confidence: high

## Source

- Source: `$request->user()`, the authenticated caller resolved by Laravel's `auth` middleware (assumed to gate this route, consistent with the guard check on the next line; not shown in the provided file).
- Sink: `Order::all()` at line 16, an unscoped Eloquent query that returns every order in the table regardless of owner.

## Fix

### File: OrderController.php

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Order;

final class OrderController
{
    public function index(Request $request): iterable
    {
        $user = $request->user();

        if ($user->isAdmin()) {
            return Order::all();
        }

        return Order::where('user_id', $user->id)->get();
    }
}
```

## Explanation

The `isAdmin()` check was negated: the branch guarded by `! $user->isAdmin()` executed `Order::all()`, so every non-admin, authenticated user received every order in the system, while the true admin branch was scoped to `Order::where('user_id', $user->id)`, giving admins only their own orders. This is a data-flow-confirmed instance of Missing Authorization - the authorization check exists and is evaluated, but the two outcomes are swapped, so the sink that should require the admin role is reached by every caller who lacks it. The fix removes the negation so the condition reads `if ($user->isAdmin())`: the unscoped `Order::all()` sink is now reached only when the caller is confirmed an admin, and non-admin, authenticated users fall through to the ownership-scoped query. No new authorization mechanism, Policy, or route middleware was introduced, and no other line changed - the fix corrects the existing check's logic rather than adding a new one, since the check itself was already present and correctly named, only inverted.

## Behaviour changes

- Non-admin authenticated users now receive only their own orders (`Order::where('user_id', $user->id)->get()`) instead of every order in the system. This is the vulnerability closing, not a new restriction beyond what the code's own branch labels already implied.
- Admin users now receive `Order::all()` (every order) instead of only their own. This restores the evident intent of the `isAdmin()` branch and does not narrow any access an admin previously had; it widens the admin's own view to match what the branch structure signals was intended, and does not touch non-admin access.
- No change to the method signature, return type, imports, or the query builder calls used (`Order::all()`, `Order::where(...)->get()`) - both call sites already existed in the file; only which branch reaches which one was corrected.
- Verification: `php -l` run against the fixed file in a scratch location (outside the case directory) reported no syntax errors. No test suite or Policy/framework harness was available in this context to exercise the route end to end; a feature test calling the route as a non-admin user and asserting the response excludes other users' orders, and as an admin asserting all orders are returned, is recommended before merging.
- Assumption: the file shown is the complete controller and no upstream check (route middleware, form request) already scopes the query differently; this is the best-supported reading given only one file was provided for the call chain.
