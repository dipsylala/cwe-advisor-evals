<?php

require_once __DIR__ . '/CartCookie.php';

final class CartController
{
    public function restore(array $cookies): array
    {
        $encoded = $cookies['cart'] ?? '';
        $cart = CartCookie::decode($encoded);

        return [
            'items' => $cart['items'] ?? [],
            'coupon' => $cart['coupon'] ?? null,
        ];
    }
}
