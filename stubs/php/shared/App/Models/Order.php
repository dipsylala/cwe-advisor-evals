<?php
// Compile-only collaborator the fixtures reference but do not ship (evals/stubs).
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * @property int $id
 * @property int $user_id
 * @property string $status
 * @property string $shipping_address
 * @property float $total
 */
class Order extends Model
{
    public function refund(): void
    {
    }
}
