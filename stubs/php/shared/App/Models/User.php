<?php
// Compile-only collaborator the fixtures reference but do not ship (evals/stubs).
namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * @property int $id
 * @property string $name
 * @property string $email
 * @property bool $is_admin
 */
class User extends Authenticatable
{
    public function isAdmin(): bool
    {
        return (bool) $this->is_admin;
    }
}
